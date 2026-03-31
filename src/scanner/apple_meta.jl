"""
    Apple metadata scanner for iOS/macOS repositories.

    Extracts and flags Apple-ecosystem identifiers that could leak
    organizational information:

      - DEVELOPMENT_TEAM values in .pbxproj files (Apple Team IDs)
      - App Group identifiers in .entitlements files
      - Signing identities and team names in ExportOptions.plist

    These are reported at MEDIUM severity because Team IDs are semi-public
    (visible in App Store metadata) but can still reveal the developer
    identity behind an otherwise anonymous repo.
"""

# ---------------------------------------------------------------------------
# File patterns to scan
# ---------------------------------------------------------------------------

const PBXPROJ_GLOB    = ".pbxproj"
const ENTITLEMENTS_EXT = ".entitlements"
const EXPORT_OPTIONS   = "ExportOptions.plist"

# Directories to skip
const APPLE_SKIP_DIRS = Set([
    ".git", "node_modules", "Pods", ".build", "build",
    "DerivedData", ".dart_tool", "vendor",
])

# ---------------------------------------------------------------------------
# Regex patterns for Apple metadata extraction
# ---------------------------------------------------------------------------

# DEVELOPMENT_TEAM = ABCDE12345; (10-char alphanumeric Team ID)
const TEAM_ID_PATTERN = r"DEVELOPMENT_TEAM\s*=\s*([A-Z0-9]{10})\s*;"

# CODE_SIGN_IDENTITY = "Apple Development: Name (ID)";
const SIGN_IDENTITY_PATTERN = r"CODE_SIGN_IDENTITY\s*=\s*\"([^\"]+)\"\s*;"

# PROVISIONING_PROFILE_SPECIFIER
const PROFILE_PATTERN = r"PROVISIONING_PROFILE_SPECIFIER\s*=\s*\"([^\"]+)\"\s*;"

# Entitlements: <string>group.com.example.app</string>
const APP_GROUP_PATTERN = r"<string>(group\.[a-zA-Z0-9._-]+)</string>"

# ExportOptions.plist: <key>teamID</key>\n<string>ABCDE12345</string>
const PLIST_TEAM_PATTERN = r"<key>teamID</key>\s*<string>([A-Z0-9]{10})</string>"

# ExportOptions.plist: <key>signingCertificate</key>\n<string>...</string>
const PLIST_SIGNING_CERT_PATTERN = r"<key>signingCertificate</key>\s*<string>([^<]+)</string>"

# ExportOptions.plist: <key>method</key>\n<string>app-store|ad-hoc|enterprise</string>
const PLIST_METHOD_PATTERN = r"<key>method</key>\s*<string>([^<]+)</string>"

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

"""
    scan_apple_metadata(repo_path::String, repo_name::String="") -> Vector{Finding}

Walk a cloned repo at `repo_path` and extract Apple development metadata.

Returns findings for Team IDs, signing identities, app group identifiers,
and export configuration -- all at MEDIUM severity.
"""
function scan_apple_metadata(repo_path::String, repo_name::String="")::Vector{Finding}
    findings  = Finding[]
    repo_name = isempty(repo_name) ? basename(repo_path) : repo_name

    if !isdir(repo_path)
        @warn "scan_apple_metadata: path is not a directory" path=repo_path
        return findings
    end

    # Collect relevant files
    pbxproj_files      = String[]
    entitlements_files = String[]
    export_plist_files = String[]

    _collect_apple_files!(repo_path, repo_path, pbxproj_files, entitlements_files, export_plist_files)

    # Scan .pbxproj files
    for filepath in pbxproj_files
        _scan_pbxproj!(findings, repo_path, filepath, repo_name)
    end

    # Scan .entitlements files
    for filepath in entitlements_files
        _scan_entitlements!(findings, repo_path, filepath, repo_name)
    end

    # Scan ExportOptions.plist files
    for filepath in export_plist_files
        _scan_export_options!(findings, repo_path, filepath, repo_name)
    end

    @info "Apple metadata scan complete" repo=repo_name findings=length(findings) pbxproj=length(pbxproj_files) entitlements=length(entitlements_files) plists=length(export_plist_files)
    return findings
end

# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

"""Recursively collect Apple-relevant files."""
function _collect_apple_files!(
    root::String, dir::String,
    pbxproj::Vector{String}, entitlements::Vector{String}, plists::Vector{String},
)
    entries = try
        readdir(dir; join=false)
    catch e
        @warn "Cannot read directory" dir exception=e
        return
    end

    for entry in entries
        full_path = joinpath(dir, entry)
        islink(full_path) && continue

        if isdir(full_path)
            entry in APPLE_SKIP_DIRS && continue
            _collect_apple_files!(root, full_path, pbxproj, entitlements, plists)
        elseif isfile(full_path)
            _, ext = splitext(entry)
            if ext == PBXPROJ_GLOB
                push!(pbxproj, full_path)
            elseif ext == ENTITLEMENTS_EXT
                push!(entitlements, full_path)
            elseif entry == EXPORT_OPTIONS
                push!(plists, full_path)
            end
        end
    end
end

# ---------------------------------------------------------------------------
# .pbxproj scanner
# ---------------------------------------------------------------------------

"""Parse a .pbxproj file for DEVELOPMENT_TEAM, CODE_SIGN_IDENTITY, etc."""
function _scan_pbxproj!(findings::Vector{Finding}, root::String, filepath::String, repo_name::String)
    relative_path = relpath(filepath, root)
    content = try
        read(filepath, String)
    catch e
        @warn "Failed to read .pbxproj" file=relative_path exception=e
        return
    end

    # Track unique Team IDs to avoid duplicate findings
    seen_teams      = Set{String}()
    seen_identities = Set{String}()

    # DEVELOPMENT_TEAM
    for m in eachmatch(TEAM_ID_PATTERN, content)
        team_id = m.captures[1]
        team_id in seen_teams && continue
        push!(seen_teams, team_id)

        line_num = _line_at_offset(content, m.offset)
        push!(findings, Finding(
            repo        = repo_name,
            severity    = MEDIUM,
            category    = APPLE_META,
            file_path   = relative_path,
            line_number = line_num,
            description = "Apple Development Team ID: $team_id",
            suggestion  = "Team IDs identify the developer/organization. Consider if this should be public.",
        ))
    end

    # CODE_SIGN_IDENTITY
    for m in eachmatch(SIGN_IDENTITY_PATTERN, content)
        identity = m.captures[1]
        identity in seen_identities && continue
        push!(seen_identities, identity)

        line_num = _line_at_offset(content, m.offset)
        push!(findings, Finding(
            repo        = repo_name,
            severity    = MEDIUM,
            category    = APPLE_META,
            file_path   = relative_path,
            line_number = line_num,
            description = "Code signing identity: $identity",
            suggestion  = "Signing identity reveals developer name. Review before making repo public.",
        ))
    end

    # PROVISIONING_PROFILE_SPECIFIER
    for m in eachmatch(PROFILE_PATTERN, content)
        profile = m.captures[1]
        line_num = _line_at_offset(content, m.offset)
        push!(findings, Finding(
            repo        = repo_name,
            severity    = LOW,
            category    = APPLE_META,
            file_path   = relative_path,
            line_number = line_num,
            description = "Provisioning profile specifier: $profile",
            suggestion  = "Provisioning profiles are environment-specific. Consider using xcconfig files to avoid committing these.",
        ))
    end
end

# ---------------------------------------------------------------------------
# .entitlements scanner
# ---------------------------------------------------------------------------

"""Parse an .entitlements file for app group identifiers."""
function _scan_entitlements!(findings::Vector{Finding}, root::String, filepath::String, repo_name::String)
    relative_path = relpath(filepath, root)
    content = try
        read(filepath, String)
    catch e
        @warn "Failed to read .entitlements" file=relative_path exception=e
        return
    end

    for m in eachmatch(APP_GROUP_PATTERN, content)
        group_id = m.captures[1]
        line_num = _line_at_offset(content, m.offset)

        push!(findings, Finding(
            repo        = repo_name,
            severity    = MEDIUM,
            category    = APPLE_META,
            file_path   = relative_path,
            line_number = line_num,
            description = "App Group identifier: $group_id",
            suggestion  = "App Group IDs contain the bundle identifier and can reveal the developer's organization.",
        ))
    end
end

# ---------------------------------------------------------------------------
# ExportOptions.plist scanner
# ---------------------------------------------------------------------------

"""Parse ExportOptions.plist for team ID, signing cert, and distribution method."""
function _scan_export_options!(findings::Vector{Finding}, root::String, filepath::String, repo_name::String)
    relative_path = relpath(filepath, root)
    content = try
        read(filepath, String)
    catch e
        @warn "Failed to read ExportOptions.plist" file=relative_path exception=e
        return
    end

    # Team ID in plist
    for m in eachmatch(PLIST_TEAM_PATTERN, content)
        team_id  = m.captures[1]
        line_num = _line_at_offset(content, m.offset)
        push!(findings, Finding(
            repo        = repo_name,
            severity    = MEDIUM,
            category    = APPLE_META,
            file_path   = relative_path,
            line_number = line_num,
            description = "ExportOptions Team ID: $team_id",
            suggestion  = "Team ID in export configuration. Consider parameterizing via environment variables.",
        ))
    end

    # Signing certificate
    for m in eachmatch(PLIST_SIGNING_CERT_PATTERN, content)
        cert     = m.captures[1]
        line_num = _line_at_offset(content, m.offset)
        push!(findings, Finding(
            repo        = repo_name,
            severity    = MEDIUM,
            category    = APPLE_META,
            file_path   = relative_path,
            line_number = line_num,
            description = "Export signing certificate: $cert",
            suggestion  = "Signing certificate name reveals the developer identity.",
        ))
    end

    # Distribution method
    for m in eachmatch(PLIST_METHOD_PATTERN, content)
        method   = m.captures[1]
        line_num = _line_at_offset(content, m.offset)

        # Enterprise distribution is more sensitive
        severity = lowercase(method) == "enterprise" ? HIGH : LOW
        push!(findings, Finding(
            repo        = repo_name,
            severity    = severity,
            category    = APPLE_META,
            file_path   = relative_path,
            line_number = line_num,
            description = "Export distribution method: $method",
            suggestion  = method == "enterprise" ?
                "Enterprise distribution is sensitive -- this reveals an enterprise developer program membership." :
                "Distribution method '$method' noted for audit record.",
        ))
    end
end

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

"""Return the 1-indexed line number for a byte offset in `text`."""
function _line_at_offset(text::String, offset::Int)::Int
    count('\n', SubString(text, 1, min(offset, lastindex(text)))) + 1
end
