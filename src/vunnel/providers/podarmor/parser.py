from __future__ import annotations

import logging
import os
from urllib.parse import urlparse

import orjson

from vunnel.utils import http


class Parser:
    _release_ = "12"
    _secdb_dir_ = "secdb"

    def __init__(
        self,
        workspace,
        url: str,
        namespace: str,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ):
        self.download_timeout = download_timeout
        self.secdb_dir_path = os.path.join(workspace.input_path, self._secdb_dir_)
        self.metadata_url = url.strip("/") if url else Parser._url_
        self.url = url
        self.namespace = namespace
        self._db_filename = self._extract_filename_from_url(url)

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    @staticmethod
    def _extract_filename_from_url(url):
        return os.path.basename(urlparse(url).path)

    def _download(self):
        """
        Downloads podarmor sec db files
        :return:
        """
        if not os.path.exists(self.secdb_dir_path):
            os.makedirs(self.secdb_dir_path, exist_ok=True)

        try:
            self.logger.info(f"downloading {self.namespace} secdb {self.url}")
            r = http.get(self.url, self.logger, stream=True, timeout=self.download_timeout)
            file_path = os.path.join(self.secdb_dir_path, self._db_filename)
            with open(file_path, "wb") as fp:
                for chunk in r.iter_content():
                    fp.write(chunk)
        except Exception:
            self.logger.exception(f"ignoring error processing secdb for {self.url}")

    def _load(self):
        """
        Loads all db json and yields it
        :return:
        """
        dbtype_data_dict = {}

        # parse and transform the json
        try:
            with open(f"{self.secdb_dir_path}/{self._db_filename}") as fh:
                dbtype_data_dict = orjson.loads(fh.read())

                yield self._release_, dbtype_data_dict
        except Exception:
            self.logger.exception(f"failed to load {self.namespace} sec db data")
            raise

    def _normalize(self, release, data):
        """
        Normalize all the sec db entries into vulnerability payload records
        :param release:
        :param dbtype_data_dict:
        :return:
        """

        vuln_dict = {}

        self.logger.debug("normalizing vulnerability data")
        
        for package in data["packages"]:
            pkg_info = package["pkg"]
            pkg_name = pkg_info["name"]
            
            # Iterate through each version and its vulnerabilities
            for version, vulnerabilities in pkg_info["secfixes"].items():
                for vuln in vulnerabilities:
                    fixedVersion = version
                    if version == "0": # "0" means that the CVE has no effect
                        continue
                    elif version == "-1":
                        fixedVersion = "None"

                    cve = vuln["CVE"]
                    severity = vuln.get("severity", "Unknown")
                    url = vuln.get("url", "")
                    
                    if cve not in vuln_dict:
                        # Create a new vulnerability record
                        vuln_dict[cve] = {
                            "Vulnerability": {
                                "Name": cve,
                                "NamespaceName": f"{self.namespace}:{release}",
                                "Link": url,
                                "Severity": severity,
                                "FixedIn": []
                            }
                        }
                    

                    fixed_info = {
                        "Name": pkg_name,
                        "Version": fixedVersion,
                        "VersionFormat": "deb",
                        "NamespaceName": f"{self.namespace}:{release}"
                    }
                    vuln_dict[cve]["Vulnerability"]["FixedIn"].append(fixed_info)

        return vuln_dict

    def get(self):
        """
        Download, load and normalize podarmor sec db and return a dict of release - list of vulnerability records
        :return:
        """
        # download the data
        self._download()

        # load the data
        for release, dbtype_data_dict in self._load():
            # normalize the loaded data
            yield release, self._normalize(release, dbtype_data_dict)
