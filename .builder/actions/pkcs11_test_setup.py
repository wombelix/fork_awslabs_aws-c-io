"""
Prepare for PKCS#11 tests by configuring SoftHSM2, if it is installed.
"""

import Builder

import os
import re


class Pkcs11TestSetup(Builder.Action):
    """
    Set up this machine for running the PKCS#11 tests.
    If SoftHSM2 cannot be installed, the tests are skipped.

    This action should be run in the 'pre_build_steps' or 'build_steps' stage.
    """

    def run(self, env):
        if not env.project.needs_tests(env):
            print("Skipping PKCS#11 setup because tests disabled for project")
            return
        return Builder.Script([
            Builder.SetupCrossCICrtEnvironment()
        ])
