/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/socket.h>

#include <aws/common/clock.h>
#include <aws/common/string.h>
#include <aws/io/logging.h>

#include <Network/Network.h>

#include <arpa/inet.h>
#include <sys/socket.h>

static int s_determine_socket_error(int error) {
    switch (error) {
        case ECONNREFUSED:
            return AWS_IO_SOCKET_CONNECTION_REFUSED;
        case ETIMEDOUT:
            return AWS_IO_SOCKET_TIMEOUT;
        case EHOSTUNREACH:
        case ENETUNREACH:
            return AWS_IO_SOCKET_NO_ROUTE_TO_HOST;
        case EADDRNOTAVAIL:
            return AWS_IO_SOCKET_INVALID_ADDRESS;
        case ENETDOWN:
            return AWS_IO_SOCKET_NETWORK_DOWN;
        case ECONNABORTED:
            return AWS_IO_SOCKET_CONNECT_ABORTED;
        case EADDRINUSE:
            return AWS_IO_SOCKET_ADDRESS_IN_USE;
        case ENOBUFS:
        case ENOMEM:
            return AWS_ERROR_OOM;
        case EAGAIN:
            return AWS_IO_READ_WOULD_BLOCK;
        case EMFILE:
        case ENFILE:
            return AWS_ERROR_MAX_FDS_EXCEEDED;
        case ENOENT:
        case EINVAL:
            return AWS_ERROR_FILE_INVALID_PATH;
        case EAFNOSUPPORT:
            return AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY;
        case EACCES:
            return AWS_ERROR_NO_PERMISSION;
        default:
            return AWS_IO_SOCKET_NOT_CONNECTED;
    }
}

static inline int s_convert_pton_error(int pton_code) {
    if (pton_code == 0) {
        return AWS_IO_SOCKET_INVALID_ADDRESS;
    }

    return s_determine_socket_error(errno);
}

/* other than CONNECTED_READ | CONNECTED_WRITE
 * a socket is only in one of these states at a time. */
enum socket_state {
    INIT = 0x01,
    CONNECTING = 0x02,
    CONNECTED_READ = 0x04,
    CONNECTED_WRITE = 0x08,
    BOUND = 0x10,
    LISTENING = 0x20,
    TIMEDOUT = 0x40,
    ERROR = 0x80,
    CLOSED,
};

struct nw_socket {
    struct aws_ref_count ref_count;
    nw_parameters_t socket_options_to_params;
    struct aws_linked_list read_queue;
    int last_error;
    aws_socket_on_readable_fn *on_readable;
    void *on_readable_user_data;
    bool setup_run;
    bool read_queued;
    bool is_listener;
};

struct socket_address {
    union sock_addr_types {
        struct sockaddr_in addr_in;
        struct sockaddr_in6 addr_in6;
        struct sockaddr_un un_addr;
    } sock_addr_types;
};

static size_t KB_16 = 16 * 1024;

static int s_setup_socket_params(struct nw_socket *nw_socket, const struct aws_socket_options *options) {
    if (options->type == AWS_SOCKET_STREAM) {
        /* if TCP, setup all the tcp options */
        if (options->domain == AWS_SOCKET_IPV4 || options->domain == AWS_SOCKET_IPV6) {
            nw_socket->socket_options_to_params =
                nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, ^(nw_protocol_options_t nw_options) {
                  if (options->connect_timeout_ms) {
                      /* this value gets set in seconds. */
                      nw_tcp_options_set_connection_timeout(
                          nw_options, options->connect_timeout_ms / AWS_TIMESTAMP_MILLIS);
                  }

                  if (options->keepalive) {
                      nw_tcp_options_set_enable_keepalive(nw_options, options->keepalive);
                  }

                  if (options->keep_alive_interval_sec) {
                      nw_tcp_options_set_keepalive_idle_time(nw_options, options->keep_alive_timeout_sec);
                  }

                  if (options->keep_alive_max_failed_probes) {
                      nw_tcp_options_set_keepalive_count(nw_options, options->keep_alive_max_failed_probes);
                  }

                  if (options->keep_alive_interval_sec) {
                      nw_tcp_options_set_keepalive_interval(nw_options, options->keep_alive_interval_sec);
                  }

                  if (g_aws_channel_max_fragment_size < KB_16) {
                      nw_tcp_options_set_maximum_segment_size(nw_options, g_aws_channel_max_fragment_size);
                  }
                });
        } else if (options->domain == AWS_SOCKET_LOCAL) {
            nw_socket->socket_options_to_params =
                nw_parameters_create_custom_ip(AF_LOCAL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
        }
    } else if (options->type == AWS_SOCKET_DGRAM) {
        nw_socket->socket_options_to_params =
            nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
    }

    if (!nw_socket->socket_options_to_params) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
    }

    nw_parameters_set_reuse_local_address(nw_socket->socket_options_to_params, true);

    return AWS_OP_SUCCESS;
}

int aws_socket_init(struct aws_socket *socket, struct aws_allocator *alloc, const struct aws_socket_options *options) {
    struct nw_socket *nw_socket = aws_mem_calloc(alloc, 1, sizeof(struct nw_socket));

    if (options) {
        if (s_setup_socket_params(nw_socket, options)) {
            return AWS_OP_ERR;
        }
    }

    aws_ref_count_init(&nw_socket->ref_count, socket, s_socket_impl_destroy);
    socket->allocator = alloc;
    socket->state = INIT;
    socket->impl = nw_socket;

    if (options) {
        socket->options = *options;
    }

    aws_linked_list_init(&nw_socket->read_queue);
    return AWS_OP_SUCCESS;
}
// TODO: probably we should just move it to dispatch queue stuff
static void s_client_set_dispatch_queue(struct aws_io_handle *handle, void *queue) {
    nw_connection_set_queue(handle->data.handle, queue);
}

static void s_client_clear_dispatch_queue(struct aws_io_handle *handle) {
    nw_connection_set_state_changed_handler(handle->data.handle, NULL);
}
static int aws_socket_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *event_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data) {
    struct nw_socket *nw_socket = socket->impl;

    AWS_ASSERT(event_loop);
    AWS_ASSERT(!socket->event_loop);

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p handle=%p: beginning connect.", (void *)socket, socket->io_handle.data.handle);
    if (socket->event_loop) {
        return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
    }
    if (socket->options.type != AWS_SOCKET_DGRAM) {
        AWS_ASSERT(on_connection_result);
        if (socket->state != INIT) {
            return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
        }
    } else { /* UDP socket */
        /* UDP sockets jump to CONNECT_READ if bind is called first */
        if (socket->state != CONNECTED_READ && socket->state != INIT) {
            return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
        }
    }

    /* fill in posix sock addr, and then let Network framework sort it out. */
    size_t address_strlen;
    if (aws_secure_strlen(remote_endpoint->address, AWS_ADDRESS_MAX_LEN, &address_strlen)) {
        return AWS_OP_ERR;
    }

    struct socket_address address;
    AWS_ZERO_STRUCT(address);
    int pton_err = 1;

    struct socket_address address;
    AWS_ZERO_STRUCT(address);
    int pton_err = 1;
    if (socket->options.domain == AWS_SOCKET_IPV4) {
        pton_err = inet_pton(AF_INET, remote_endpoint->address, &address.sock_addr_types.addr_in.sin_addr);
        address.sock_addr_types.addr_in.sin_port = htons(remote_endpoint->port);
        address.sock_addr_types.addr_in.sin_family = AF_INET;
        address.sock_addr_types.addr_in.sin_len = sizeof(struct sockaddr_in);
    } else if (socket->options.domain == AWS_SOCKET_IPV6) {
        pton_err = inet_pton(AF_INET6, remote_endpoint->address, &address.sock_addr_types.addr_in6.sin6_addr);
        address.sock_addr_types.addr_in6.sin6_port = htons(remote_endpoint->port);
        address.sock_addr_types.addr_in6.sin6_family = AF_INET6;
        address.sock_addr_types.addr_in6.sin6_len = sizeof(struct sockaddr_in6);
    } else if (socket->options.domain == AWS_SOCKET_LOCAL) {
        address.sock_addr_types.un_addr.sun_family = AF_UNIX;
        strncpy(address.sock_addr_types.un_addr.sun_path, remote_endpoint->address, AWS_ADDRESS_MAX_LEN);
        address.sock_addr_types.un_addr.sun_len = sizeof(struct sockaddr_un);

    } else {
        AWS_ASSERT(0);
        return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
    }

    if (pton_err != 1) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to parse address %s:%d.",
            (void *)socket,
            socket->io_handle.data.handle,
            remote_endpoint->address,
            (int)remote_endpoint->port);
        return aws_raise_error(s_convert_pton_error(pton_err));
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: connecting to endpoint %s:%d.",
        (void *)socket,
        socket->io_handle.data.handle,
        remote_endpoint->address,
        (int)remote_endpoint->port);

    socket->state = CONNECTING;
    socket->remote_endpoint = *remote_endpoint;
    socket->connect_accept_user_data = user_data;
    socket->connection_result_fn = on_connection_result;

    nw_endpoint_t endpoint = nw_endpoint_create_address((struct sockaddr *)&address.sock_addr_types);

    if (!endpoint) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to create remote address %s:%d.",
            (void *)socket,
            socket->io_handle.data.handle,
            remote_endpoint->address,
            (int)remote_endpoint->port);
        return aws_raise_error(AWS_IO_SOCKET_INVALID_ADDRESS);
    }

    socket->io_handle.data.handle = nw_connection_create(endpoint, nw_socket->socket_options_to_params);
    nw_release(endpoint);

    if (!socket->io_handle.data.handle) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: connection creation failed, presumably due to a bad network path.",
            (void *)socket,
            socket->io_handle.data.handle);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    socket->io_handle.set_queue = s_client_set_dispatch_queue;
    socket->io_handle.clear_queue = s_client_clear_dispatch_queue;

    aws_event_loop_connect_handle_to_completion_port(event_loop, &socket->io_handle);
    socket->event_loop = event_loop;

    /* set a handler for socket state changes. This is where we find out the connection timed out, was successful, was
     * disconnected etc .... */
    nw_connection_set_state_changed_handler(
        socket->io_handle.data.handle, ^(nw_connection_state_t state, nw_error_t error) {
          /* we're connected! */
          if (state == nw_connection_state_ready) {
              AWS_LOGF_INFO(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: connection success",
                  (void *)socket,
                  socket->io_handle.data.handle);

              nw_path_t path = nw_connection_copy_current_path(socket->io_handle.data.handle);
              nw_endpoint_t local_endpoint = nw_path_copy_effective_local_endpoint(path);
              nw_release(path);
              const char *hostname = nw_endpoint_get_hostname(local_endpoint);
              uint16_t port = nw_endpoint_get_port(local_endpoint);

              size_t hostname_len = strlen(hostname);
              size_t buffer_size = AWS_ARRAY_SIZE(socket->local_endpoint.address);
              size_t to_copy = aws_min_size(hostname_len, buffer_size);
              memcpy(socket->local_endpoint.address, hostname, to_copy);
              socket->local_endpoint.port = port;
              nw_release(local_endpoint);

              AWS_LOGF_DEBUG(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: local endpoint %s:%d",
                  (void *)socket,
                  socket->io_handle.data.handle,
                  socket->local_endpoint.address,
                  port);

              socket->state = CONNECTED_WRITE | CONNECTED_READ;
              aws_ref_count_acquire(&nw_socket->ref_count);
              on_connection_result(socket, AWS_OP_SUCCESS, user_data);
              aws_ref_count_release(&nw_socket->ref_count);
              nw_socket->setup_run = true;
          } else if (error) {
              /* any error, including if closed remotely in error */
              int error_code = nw_error_get_error_code(error);

              AWS_LOGF_ERROR(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: connection error %d",
                  (void *)socket,
                  socket->io_handle.data.handle,
                  error_code);

              /* we don't let this thing do DNS or TLS. Everything had better be a posix error. */
              AWS_ASSERT(nw_error_get_error_domain(error) == nw_error_domain_posix);
              error_code = s_determine_socket_error(error_code);
              nw_socket->last_error = error_code;
              aws_raise_error(error_code);
              socket->state = ERROR;
              aws_ref_count_acquire(&nw_socket->ref_count);
              if (!nw_socket->setup_run) {
                  on_connection_result(socket, error_code, user_data);
                  nw_socket->setup_run = true;
              } else if (socket->readable_fn) {
                  socket->readable_fn(socket, nw_socket->last_error, socket->readable_user_data);
              }
              aws_ref_count_release(&nw_socket->ref_count);
          } else if (state == nw_connection_state_cancelled) {
              /* this should only hit when the socket was closed by not us. Note,
               * we uninstall this handler right before calling close on the socket so this shouldn't
               * get hit unless it was triggered remotely */
              AWS_LOGF_DEBUG(
                  AWS_LS_IO_SOCKET, "id=%p handle=%p: socket closed", (void *)socket, socket->io_handle.data.handle);
              socket->state = CLOSED;
              aws_ref_count_acquire(&nw_socket->ref_count);
              aws_raise_error(AWS_IO_SOCKET_CLOSED);
              if (!nw_socket->setup_run) {
                  on_connection_result(socket, AWS_IO_SOCKET_CLOSED, user_data);
                  nw_socket->setup_run = true;
              } else if (socket->readable_fn) {
                  socket->readable_fn(socket, AWS_IO_SOCKET_CLOSED, socket->readable_user_data);
              }
          }
        });
    nw_connection_start(socket->io_handle.data.handle);
    nw_retain(socket->io_handle.data.handle);

    return AWS_OP_SUCCESS;
}
