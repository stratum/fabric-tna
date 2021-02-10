# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0
from abc import ABC, abstractclassmethod, abstractmethod
from argparse import ArgumentParser

from trex.astf.api import ASTFClient
from trex_stl_lib.api import STLClient


class BaseTest(ABC):
    @abstractmethod
    def start(self, args: dict = {}) -> None:
        """
        Start the test

        :parameters:
            args: dict
                The test arguments
        """
        pass

    @abstractclassmethod
    def test_type(cls) -> str:
        """
        Get test type, for example: stateless or stateful
        """
        return None

    @classmethod
    def setup_subparser(cls, parser: ArgumentParser) -> None:
        """
        Initialize the subparser

        :parameters:
            parser: ArgumentParser
                The parent argument parser
        """
        pass


class StatelessTest(BaseTest):
    client: STLClient

    def __init__(self, client: STLClient) -> None:
        """
        Create and initialize a test

        :parameters:
            client: STLClient
                The Trex statelesss client
        """
        self.client = client

    @classmethod
    def test_type(cls) -> str:
        return "stateless"


class StatefulTest(BaseTest):
    client: ASTFClient

    def __init__(self, client: ASTFClient) -> None:
        """
        Create and initialize a test

        :parameters:
            client: ASTFClient
                The Trex advance stateful client
        """
        self.client = client

    @classmethod
    def test_type(cls) -> str:
        return "astf"
