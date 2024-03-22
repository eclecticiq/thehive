#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
import requests


class EclecticIQAnalyzer(Analyzer):
    """Searches for given Observables in configured EclecticIQ instance.
    All standard Cortex data types are supported."""

    def __init__(self):
        Analyzer.__init__(self)

        self.service = self.get_param("config.service", "search_observable", None)

        self.name = self.get_param(
            "config.name", None, "No EclecticIQ instance name given."
        )
        self.url = self.get_param("config.url", None, "No EclecticIQ url given.")
        self.key = self.get_param("config.key", None, "No EclecticIQ api key given.")
        self.data = self.get_param("data", None, "Data is missing")

        if self.get_param("config.cert_check", True):
            self.ssl = self.get_param("config.cert_path", True)
        else:
            self.ssl = False

        self.session = requests.Session()
        self.session.verify = self.ssl
        self.session.proxies = self.get_param("config.proxy", None)
        self.session.headers.update(
            {"Accept": "application/json", "Authorization": f"Bearer {self.key}"}
        )

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "EIQ"
        predicate = "API"

        found = 0

        if raw["results"].get("entities", []):
            found += len(raw["results"]["entities"])

        value = f"Found {found} entities" if found > 0 else "Not found"
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def get_source(self, url):
        response = self.session.get(url)
        return response.json()["data"]["name"]

    def get_confidence(self, data):
        confidence = data.get("confidence", None)
        if isinstance(confidence, dict):
            confidence = confidence.get("value")
        return confidence

    def run(self):
        """
        Query EclecticIQ instance for data by querying observable for
        observable id and then querying entities endpoint for parent entities

        Return dict response to cortex
        """

        results = {}  # empty dict to hold final results

        url = self.url + "/api/v2/observables"  # set observable url
        params = {"filter[value]": self.data}  # use data in filter param

        response = self.session.get(url, params=params)

        if not response.json().get("count"):  # exit early for no data
            return self.report(results)
        data = response.json()["data"]

        obs_id = data[0]["id"]
        obs_type = data[0]["type"]
        obs_score = data[0].get("meta", {}).get("maliciousness")

        url = self.url + "/api/v2/entities"  # set entity url
        params = {"filter[observables]": obs_id}  # use observable id in filter param

        response = self.session.get(url, params=params)
        response_json = response.json()

        if not response_json.get("count"):  # exit early for no data
            return self.report(results)

        response_entities = response_json["data"]  # list of entity dicts
        entities = []
        for entity in response_entities:
            source_name = self.get_source(entity["sources"][0])
            entity_data = entity.get("data", {})
            entities.append(
                {
                    "id": entity["id"],
                    "title": entity_data.get("title"),
                    "type": entity_data.get("type"),
                    "confidence": self.get_confidence(entity_data),
                    "tags": entity.get("meta", {}).get("tags"),
                    "timestamp": entity.get("meta", {}).get(
                        "estimated_threat_start_time"
                    ),
                    "source_name": source_name,
                }
            )

        results["count"] = response_json["count"]
        results["entities"] = entities
        results["name"] = self.name
        results["url"] = self.url
        results["obs_type"] = obs_type
        results["obs_value"] = self.data
        results["obs_score"] = obs_score
        self.report({"results": results})


if __name__ == "__main__":
    EclecticIQAnalyzer().run()
