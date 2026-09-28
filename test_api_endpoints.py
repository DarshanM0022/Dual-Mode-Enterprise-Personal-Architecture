import unittest
from fastapi.testclient import TestClient
from src.app import app

class TestAPIEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "HEALTHY")

    def test_index_html(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("AETHERIS", res.text)
        self.assertIn("Unified Adaptive Security Platform", res.text)

    def test_siem_events(self):
        res = self.client.get("/api/siem/events")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("events", data)
        self.assertGreater(data["total"], 0)

    def test_siem_ingest_windows(self):
        payload = {
            "EventID": 4624,
            "TargetUserName": "jdoe_contractor",
            "WorkstationName": "ACME-CONTRACTOR-01",
            "IpAddress": "10.20.10.99"
        }
        res = self.client.post("/api/siem/ingest", json=payload)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "INGESTED")

    def test_entities_users(self):
        res = self.client.get("/api/entities/users")
        self.assertEqual(res.status_code, 200)
        users = res.json()
        self.assertGreater(len(users), 0)

    def test_entities_devices(self):
        res = self.client.get("/api/entities/devices")
        self.assertEqual(res.status_code, 200)
        devices = res.json()
        self.assertGreater(len(devices), 0)

    def test_risk_profile(self):
        res = self.client.get("/api/risk/profile/usr-elena-finance")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("overall_risk", data)
        self.assertIn("primary_drivers", data)

    def test_blast_radius(self):
        res = self.client.get("/api/risk/blast-radius/usr-elena-finance?max_hops=2")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("blast_radius_score", data)
        self.assertIn("reachable_assets", data)

    def test_entity_graph(self):
        res = self.client.get("/api/risk/graph")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)

    def test_incidents(self):
        res = self.client.get("/api/incidents")
        self.assertEqual(res.status_code, 200)
        incidents = res.json()
        self.assertGreater(len(incidents), 0)

    def test_ai_copilot_query(self):
        payload = {"prompt": "Why is Elena Rostova high risk?"}
        res = self.client.post("/api/ai/query", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "COMPLETED")
        self.assertIn("usr-elena-finance", data["content"])

if __name__ == "__main__":
    unittest.main()
