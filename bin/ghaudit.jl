#!/usr/bin/env julia

# GHAudit CLI entrypoint
# Usage: julia bin/ghaudit.jl <command> [options]

# Activate project environment
using Pkg
Pkg.activate(joinpath(@__DIR__, ".."))

# Load module
include(joinpath(@__DIR__, "..", "src", "GHAudit.jl"))

# Run CLI
GHAudit.run_cli()
