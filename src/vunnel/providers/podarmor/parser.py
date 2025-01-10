from __future__ import annotations

import copy
import logging
import os
from typing import TYPE_CHECKING, Any

import orjson

if TYPE_CHECKING:

    from vunnel import workspace

from vunnel.utils import http, vulnerability


class Parser:
    _release_ = "12"
    _secdb_dir_ = "secdb"

    def __init__(
        self,
        workspace: workspace.Workspace,
        url: str,
        namespace: str,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ) -> None:
        self.download_timeout = download_timeout
        self.secdb_dir_path = os.path.join(workspace.input_path, self._secdb_dir_)
        self.url = url
        self.namespace = namespace
        self._db_filename = "security.json"

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def _download(self) -> None:
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

    def _load(self) -> Any:
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

    def _normalize(self, release: str, data: Any) -> dict[str, dict[str, Any]]:
        """
        Normalize all the sec db entries into vulnerability payload records
        :param release:
        :param dbtype_data_dict:
        :return:
        """

        vuln_dict: dict[str, Any] = {}

        self.logger.debug("normalizing vulnerability data")

        for package in data["packages"]:
            pkg_info = package["pkg"]
            pkg_name = pkg_info["name"]

            # iterate through each version and the fixed vulnerabilities
            for version, vulns in pkg_info["secfixes"].items():
                for cve in vulns:
                    if cve not in vuln_dict:
                        # create a new vulnerability record
                        vuln_dict[cve] = copy.deepcopy(vulnerability.vulnerability_element)
                        vuln_record = vuln_dict[cve]

                        vuln_record["Vulnerability"]["Name"] = cve
                        vuln_record["Vulnerability"]["NamespaceName"] = f"{self.namespace}:{release}"

                        reference_links = vulnerability.build_reference_links(cve)
                        if reference_links:
                            vuln_record["Vulnerability"]["Link"] = reference_links[0]
                        vuln_record["Vulnerability"]["Severity"] = "Unknown"
                    else:
                        vuln_record = vuln_dict[cve]

                    fixedVersion = version
                    if version == "0":  # "0" means that the CVE has no effect
                        continue
                    if version == "-1":
                        fixedVersion = "None"
                    fixed_info = {
                        "Name": pkg_name,
                        "Version": fixedVersion,
                        "VersionFormat": "deb",
                        "NamespaceName": f"{self.namespace}:{release}",
                    }
                    vuln_record["Vulnerability"]["FixedIn"].append(fixed_info)
        return vuln_dict

    def get(self) -> Any:
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
