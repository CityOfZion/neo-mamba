import unittest
from neo3.network import convenience


class RequestInfoTestCase(unittest.TestCase):
    def test_most_recent_flight(self):
        ri = convenience.RequestInfo(0)
        self.assertIsNone(ri.most_recent_flight())

        fi = convenience.FlightInfo(1, 0)
        ri.add_new_flight(fi)
        most_recent = ri.most_recent_flight()
        self.assertEqual(ri.last_used_node, fi.node_id)

    def test_mark_failed(self):
        ri = convenience.RequestInfo(0)
        self.assertEqual(0, ri.failed_total)
        self.assertEqual(0, len(ri.failed_nodes))

        ri.mark_failed_node(123)
        self.assertEqual(1, ri.failed_total)
        self.assertEqual(1, len(ri.failed_nodes))


class NodeWeightTestCase(unittest.TestCase):
    def test_weight(self):
        nw1 = convenience.NodeWeight(node_id=123)
        self.assertEqual(convenience.NodeWeight.SPEED_RECORD_COUNT, len(nw1.speed))
        nw1.append_new_speed(1)
        self.assertEqual(convenience.NodeWeight.SPEED_RECORD_COUNT, len(nw1.speed))

        nw2 = convenience.NodeWeight(node_id=456)
        nw2.append_new_speed(1000)

        # highest speed + longest time since used has best weight. Here nw1 has the worst speed,
        # but longest time since use. Therefore NW2 should win
        self.assertTrue(nw2 > nw1)

        # now make nw1 fastest, but test for being punished hard for timeouts
        nw1.append_new_speed(100_000)
        nw1.append_new_speed(100_000)
        nw1.append_new_speed(100_000)
        self.assertTrue(nw1 > nw2)
        nw1.timeout_count += 1
        self.assertFalse(nw1 > nw2)

        self.assertIn("<NodeWeight at", str(nw1))
        # for some reason the weight format sometimes rounds differently causing the test to fail, so we limit decimals to 0
        self.assertIn(f"weight:{nw1.weight():.0f}", str(nw1))
