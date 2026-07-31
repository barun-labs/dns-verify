import os
import sys
import pytest

# Add parent directory to path so we can import dns_verify
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import dns_verify

def test_parse_dig_output_noerror():
    output = """;; ANSWER SECTION:
example.com.            475     IN      A       93.184.216.34
;; Query time: 10 msec
status: NOERROR"""
    res = dns_verify.parse_dig_output("example.com", "1.1.1.1", output, 0)
    assert res["status"] == "NOERROR"
    assert res["ip"] == "93.184.216.34"
    assert res["qtime"] == "10ms"

def test_parse_dig_output_cname():
    output = """;; ANSWER SECTION:
example.com.            475     IN      CNAME   target.example.com.
;; Query time: 15 msec
status: NOERROR"""
    res = dns_verify.parse_dig_output("example.com", "1.1.1.1", output, 0)
    assert res["status"] == "NOERROR"
    assert res["cname"] == "target.example.com"
    assert res["ip"] == "[CNAME ONLY]"

def test_parse_dig_output_nxdomain():
    output = """status: NXDOMAIN
;; Query time: 5 msec"""
    res = dns_verify.parse_dig_output("nonexistent.domain", "1.1.1.1", output, 0)
    assert res["status"] == "NXDOMAIN"
    assert res["ip"] == "[NXDOMAIN]"

def test_query_single_dns_basic():
    # Simple check that the command works for a known good domain
    res = dns_verify.query_single_dns("google.com", "8.8.8.8")
    assert res["status"] == "NOERROR"
    assert res["ip"] != "TIMEOUT / ERROR"
    assert "ms" in res["qtime"]

def test_run_benchmark_queries():
    res = dns_verify.run_benchmark_queries("google.com", "8.8.8.8", "A", 2, None, False, False, 3)
    assert res is not None
    assert "ms" in res["qtime"]
    assert "/" in res["qtime"]  # avg/min/max format

def test_run_dns_verification():
    domains = ["example.com"]
    servers = ["1.1.1.1"]
    results = dns_verify.run_dns_verification(domains, servers)
    assert len(results) == 1
    assert results[0]["domain"] == "example.com"
    assert results[0]["server"] == "1.1.1.1"
