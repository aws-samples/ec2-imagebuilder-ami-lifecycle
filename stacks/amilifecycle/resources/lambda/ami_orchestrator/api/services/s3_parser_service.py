#!/usr/bin/env python

"""
    s3_parser_service.py:
    service that provides utilites for parsing different parts of an S3 url.
"""

import logging
from urllib.parse import urlparse

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

class S3ParserService:
    """
        Service that provides utilites for parsing different parts of an S3 url.
    """

    def __init__(self, url):
        self._parsed = urlparse(url, allow_fragments=False)

    @property
    def bucket(self) -> str:
        return self._parsed.netloc

    @property
    def key(self) -> str:
        if self._parsed.query:
            return self._parsed.path.lstrip('/') + '?' + self._parsed.query
        else:
            return self._parsed.path.lstrip('/')

    @property
    def url(self) -> str:
        return self._parsed.geturl()
