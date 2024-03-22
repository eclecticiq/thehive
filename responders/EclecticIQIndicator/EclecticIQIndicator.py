#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
from typing import Optional

import requests
import json
import traceback
import uuid

from cortexutils.responder import Responder


class EclecticIQIndicator(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.eiq_host_url = self.get_param(
            "config.eiq_host_url",
            None,
            "EclecticIQ Intelligence Center host URL (e.g.:https://demo.eclecticiq.com)",
        )
        self.apikey = self.get_param(
            "config.eiq_api_key", None, "EclecticIQ Intelligence Center API key missing"
        )
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.apikey}",
        }
        self.group_name = self.get_param(
            "config.group_name",
            "Testing Group",
            "EclecticIQ Intelligence Center Group Name (e.g.:Testing Group)",
        )

    @staticmethod
    def convert_eiq_observable_type(value):
        ioc_types = {
            "address": "address",
            "asn": "asn",
            "cve": "cve",
            "domain": "domain",
            "email": "email",
            "file": "file",
            "filename": "file",
            "fqdn": "host",
            "hash": "hash-sha256",
            "host": "host",
            "imphash": "hash-imphash",
            "ip": "ipv4",
            "ipv4": "ipv4",
            "ipv4-addr": "ipv4",
            "ipv4-net": "ipv4-cidr",
            "ipv6": "ipv6",
            "ipv6-addr": "ipv6",
            "ipv6-net": "ipv6-cidr",
            "mac": "mac-48",
            "mail": "email",
            "mail_subject": "email-subject",
            "md5": "hash-md5",
            "mutex": "mutex",
            "organization": "organization",
            "phone_number": "telephone",
            "registry": "registrar",
            "sha256": "hash-sha256",
            "sha384": "hash-sha384",
            "sha512": "hash-sha512",
            "uri": "uri",
            "uri_path": "uri",
            "url": "uri",
            "user-agent": "user-agent",
        }
        return ioc_types.get(value.lower())

    @staticmethod
    def format_time(value):
        if value:
            return datetime.fromtimestamp(value // 1000).isoformat()
        return None

    @staticmethod
    def get_max(value1: Optional[int], value2: Optional[int]) -> Optional[int]:
        if value1 and value2:
            return max(value2, value1)
        return value1 or value2

    def get_report(self, case_data, source_id):
        desc_fields = [
            ("title", "Case Title"),
            ("description", "Case Description"),
            ("summary", "Case Summary"),
        ]
        description = ""
        for field, title in desc_fields:
            if case_data.get(field):
                description += f"<p><strong>{title}:</strong> {case_data[field]}</p>"

        # process tag data
        tags = ["Hive", "Cortex", "Responder"]  # some default tags

        case_tags = case_data.get("tags", None)
        if case_tags is not None:
            tags.extend(case_tags)

        severity_map = {
            1: "LOW",
            2: "MEDIUM",
            3: "HIGH",
            4: "CRITICAL",
        }

        confidence_map = {1: "Low", 2: "Medium", 3: "High", 4: "High"}

        confidence = confidence_map.get(case_data.get("severity"))
        case_data["severity"] = severity_map.get(case_data.get("severity"))

        case_tag_fields = [
            ("caseId", "Case ID"),
            ("severity", "Severity"),
            ("impactStatus", "Impact Status"),
            ("resolutionStatus", "Resolution Status"),
            ("status", "Status"),
            ("stage", "Stage"),
            ("owner", "Owner"),
        ]
        for tag_field, title in case_tag_fields:
            value = case_data.get(tag_field)
            if value:
                tags.append(f"{title}: {value}")
                description += f"<p><strong>{title}:</strong> {value}</p>"

        # PROCESS TLP
        tlp_pap_map = {
            0: "WHITE",
            1: "GREEN",
            2: "AMBER",
            3: "RED",
        }
        case_tlp = case_data.get("tlp", None)
        if case_tlp and tlp_pap_map.get(case_tlp):
            case_tlp = tlp_pap_map[case_tlp]

        # PROCESS PAP
        case_pap = case_data.get("pap", None)
        if case_pap and tlp_pap_map.get(case_pap):
            tags.append(f"PAP: {tlp_pap_map[case_pap]}")

        # deduplicate tags
        tags = list(set(tags))

        _id = "{{https://thehive5.myorg/}}report-{}".format(
            str(uuid.uuid5(uuid.NAMESPACE_X500, case_data.get("id")))
        )

        report = {
            "data": {
                "id": _id,
                "title": f"{case_data.get('title')} - {case_data.get('caseId')}",
                "description": description,
                "type": "report",
            },
            "meta": {
                "estimated_observed_time": self.format_time(
                    case_data.get("updatedAt", None)
                ),
                "estimated_threat_start_time": self.format_time(
                    case_data.get("startDate", None)
                ),
                "tags": tags,
                "tlp_color": case_tlp,
            },
            "sources": [{"source_id": source_id}],
        }

        if confidence:
            report["data"]["confidence"] = dict(type="confidence", value=confidence)
        return report

    def get_indicator(self, hive_data, source_id):
        if not self.convert_eiq_observable_type(hive_data.get("dataType")):
            self.error("Unsupported IOC type")
            return None

        ioc_value = hive_data.get("data", None)
        description = ""

        # process tag data
        tags = ["Hive", "Cortex", "Responder"]  # some default tags

        observable_type = hive_data.get("_type", None)
        if observable_type is not None:
            tags.append(observable_type)
            description += f"<p><strong>Type:</strong> {observable_type}</p>"

        observable_id = hive_data.get("id", None)
        if observable_id is not None:
            tags.append("Observable ID: {}".format(observable_id))
            description += f"<p><strong>Observable ID:</strong> {observable_id}</p>"

        tags.extend(hive_data.get("tags", []))

        sighted = hive_data.get("sighted", None)
        if sighted is True:
            tags.append("Sighted")
            description += f"<p><strong>Sighted:</strong> True</p>"

        # PROCESS TLP
        tlp_pap_map = {
            0: "WHITE",
            1: "GREEN",
            2: "AMBER",
            3: "RED",
        }
        tlp = hive_data.get("tlp", None)
        tlp_color = tlp_pap_map.get(tlp, None) if tlp else None

        # PROCESS PAP

        pap = hive_data.get("pap", None)
        if pap and tlp_pap_map.get(pap):
            tags.append(f"PAP: {tlp_pap_map[pap]}")

        # deduplicate tags
        tags = list(set(tags))

        _id = "{{https://thehive5.myorg/}}indicator-{}".format(
            str(uuid.uuid5(uuid.NAMESPACE_X500, hive_data["id"]))
        )

        indicator = {
            "data": {
                "id": _id,
                "title": ioc_value,  # use the main value as the title
                "description": description,  # use hive description fields combined
                "type": "indicator",
                "extracts": [
                    {
                        "kind": self.convert_eiq_observable_type(
                            hive_data.get("dataType")
                        ),
                        "value": ioc_value,
                    }
                ],
            },
            "meta": {
                "estimated_observed_time": self.format_time(
                    hive_data.get("updatedAt", None)
                ),
                "estimated_threat_start_time": self.format_time(
                    hive_data.get("startDate", None)
                ),
                "tags": tags,
                "tlp_color": tlp_color,
            },
            "sources": [{"source_id": source_id}],
        }
        return indicator

    def get_group_source_id(self):
        response = requests.get(
            self.eiq_host_url + "/private/groups/",
            params=f"filter[name]={self.group_name}",
            headers=self.headers,
        )
        if response.status_code != 200:
            return None
        return response.json()["data"][0]["source"]

    def create_relation(self, entity_dict, source_id):
        report_id, indicator_id = entity_dict.get("report"), entity_dict.get(
            "indicator"
        )

        if report_id and indicator_id:
            relation_id = str(
                uuid.uuid5(uuid.NAMESPACE_X500, f"{report_id}-{indicator_id}")
            )
            relationship = {
                "data": [
                    {
                        "id": relation_id,
                        "data": {
                            "source": report_id,
                            "key": "reports",
                            "target": indicator_id,
                        },
                        "sources": [source_id],
                    }
                ]
            }

            response = requests.put(
                self.eiq_host_url + "/api/v2/relationships",
                json=relationship,
                headers=self.headers,
            )
            return response

    def run(self):
        try:
            Responder.run(self)

            hive_data = self.get_param("data")
            _type = hive_data.get("_type")
            if _type not in ["case", "case_artifact"]:
                self.error("Responder not supported")

            source_id = self.get_group_source_id()
            if not source_id:
                self.error("Invalid Group name")
                return

            case_data = hive_data if _type == "case" else hive_data.get("case")
            report = self.get_report(case_data, source_id)

            indicator = None
            if _type == "case_artifact":
                indicator = self.get_indicator(hive_data, source_id)
                if not indicator:
                    self.error("Unsupported IOC type")
                    return None

            data = []
            report and data.append(report)
            indicator and data.append(indicator)

            # case data contains parent case information
            json_data = dict(data=data)

            response = requests.put(
                self.eiq_host_url + "/api/v2/entities",
                json=json_data,
                headers=self.headers,
            )
            if response.status_code not in [200, 201]:
                self.error(f"While making the call, receiving {response.status_code}")
                return

            response = response.json()
            entity_ids = {
                data["data"]["type"]: data["id"] for data in response.get("data", [])
            }

            relation_response = self.create_relation(entity_ids, source_id)
            if relation_response and relation_response.status_code not in [200, 201]:
                self.error(
                    f"While making the relationship, receiving status: {response.status_code}"
                )
                return

            result = {"message": "Submitted to EclecticIQ Intelligence Center"}
            if entity_ids.get("report"):
                result["report_platform_link"] = (
                    f"{self.eiq_host_url}/entity/{entity_ids.get('report')}"
                )

            if entity_ids.get("indicator"):
                result["indicator_platform_link"] = (
                    f"{self.eiq_host_url}/entity/{entity_ids.get('indicator')}"
                )

            self.report(result)
        except Exception as ex:
            self.error("Error: {}: ex: {}".format(traceback.format_exc(), ex))

    def operations(self, raw):
        return [
            self.build_operation("AddTagToArtifact", tag="EclecticIQ:Indicator Created")
        ]


if __name__ == "__main__":
    EclecticIQIndicator().run()