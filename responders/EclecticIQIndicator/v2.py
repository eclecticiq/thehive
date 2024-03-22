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

    def run(self):
        indicator = {}
        try:
            Responder.run(self)
            ioctypes = {  # hard-code a supported observable type list here
                "hash": "hash-sha256",
                "sha256": "hash-sha256",
                "md5": "hash-md5",
                "sha1": "hash-sha1",
                "ip": "ipv4",
                "ip6": "ipv6",
                "ipv6": "ipv6",
                "domain": "domain",
                "url": "uri",
                "email": "email",
            }

            # hive data contains case and observable information
            hive_data = self.get_param("data")

            data_type = hive_data.get("dataType")
            if data_type not in ioctypes:
                self.error("Unsupported IOC type")
                return
            ioc = hive_data.get("data", None)

            # case data contains parent case information
            case_data = hive_data.get("case")

            desc_fields = [
                ("title", "Case Title"),
                ("description", "Case Description"),
                ("summary", "Case Summary"),
            ]
            description = ""
            for field, title in desc_fields:
                if case_data.get(field):
                    description += (
                        f"<p><strong>{title}:</strong> {case_data[field]}</p>"
                    )

            # process time data
            obs_updated = self.format_time(hive_data.get("updatedAt", None))
            obs_start = self.format_time(hive_data.get("startDate", None))

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

            parent_tags = hive_data.get("tags", None)
            if parent_tags is not None:
                tags.extend(parent_tags)

            sighted = hive_data.get("sighted", None)
            if sighted is True:
                tags.append("Sighted")
                description += f"<p><strong>Sighted:</strong> True</p>"

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
            observable_tlp = hive_data.get("tlp", None)
            case_tlp = case_data.get("tlp", None)
            tlp = self.get_max(observable_tlp, case_tlp)
            tlp_color = tlp_pap_map.get(tlp, None) if tlp else None

            # PROCESS PAP

            observable_pap = hive_data.get("pap", None)
            case_pap = case_data.get("pap", None)
            pap = self.get_max(observable_pap, case_pap)
            if pap and tlp_pap_map.get(pap):
                tags.append(f"PAP: {tlp_pap_map[pap]}")

            # deduplicate tags
            tags = list(set(tags))

            _id = "{{https://thehive5.myorg/}}indicator-{}".format(
                str(uuid.uuid5(uuid.NAMESPACE_X500, ioc))
            )

            indicator = {
                "data": {
                    "data": {
                        "id": _id,
                        "title": ioc,  # use the main value as the title
                        "description": description,  # use hive description fields combined
                        "type": "indicator",
                        "extracts": [
                            {
                                "kind": data_type,
                                "value": ioc,
                            }
                        ],
                    },
                    "meta": {
                        "estimated_observed_time": obs_updated,
                        "estimated_threat_start_time": obs_start,
                        "tags": tags,
                        "tlp_color": tlp_color,
                    },
                }
            }

            if confidence:
                indicator["data"]["data"]["confidence"] = dict(
                    type="confidence", value=confidence
                )

            response = requests.post(
                self.eiq_host_url + "/api/v2/entities",
                json=indicator,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer {}".format(self.apikey),
                },
            )

            response = json.loads(response.text)
            self.report(
                {
                    "message": ioc
                    + " Submitted indicator to EclecticIQ Intelligence Center API",
                    "platform_link": self.eiq_host_url
                    + "/entity/"
                    + response["data"]["id"],
                }
            )
        except Exception as ex:
            self.error("Error: {}: ex: {}".format(traceback.format_exc(), ex))

    def operations(self, raw):
        return [
            self.build_operation("AddTagToArtifact", tag="EclecticIQ:Indicator Created")
        ]


if __name__ == "__main__":
    EclecticIQIndicator().run()
