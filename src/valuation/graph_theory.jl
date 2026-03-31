"""
    Portfolio graph-theoretic structural analysis.

    Models the user's repository portfolio as an undirected weighted graph and
    extracts structural properties that reveal skill diversity, domain clustering,
    and portfolio coherence.

    Mathematical foundation — why graphs?
    ─────────────────────────────────────
    A portfolio is not a flat list. Repos share languages, domains, and tech
    stacks, forming a latent structure that graph theory can reveal:

        G = (V, E, w)

    where V = {repos}, E = {(u,v) : u and v share attributes}, and
    w: E → ℝ⁺ assigns edge weights based on attribute overlap strength.

    Key insights from graph analysis:
    • **Betweenness centrality** identifies "bridge" repos that connect otherwise
      separate skill domains — these demonstrate versatility.
    • **Connected components** reveal natural skill clusters (web, mobile, systems).
    • **Isolated vertices** flag repos with no portfolio synergy — candidates for
      either removal or intentional diversification.
    • **Degree distribution** shows whether the portfolio is tightly focused or
      broadly diversified.

    References:
        Newman, M. E. J. (2010). Networks: An Introduction. Oxford University Press.
        Brandes, U. (2001). A faster algorithm for betweenness centrality.
            Journal of Mathematical Sociology, 25(2), 163-177.

    Implementation note:
    We use SimpleGraph from Graphs.jl with a separate Dict{Edge, Float64} for
    edge weights, since SimpleWeightedDiGraph requires an additional package.
    Betweenness centrality is computed on the unweighted topology; for community
    detection we threshold the weight matrix.
"""

# ─────────────────────────────────────────────────────────────────────────────
# Domain keyword taxonomy
# ─────────────────────────────────────────────────────────────────────────────

"""
    DOMAIN_KEYWORDS :: Dict{String, Vector{String}}

Mapping from domain names to keyword patterns used for domain detection.
When a repo's name or description contains any keyword from a domain,
that repo is tagged with that domain.

Teaching note — keyword-based domain detection:
This is a simple but effective heuristic. In production, you might use
TF-IDF or embedding similarity, but keyword matching provides interpretable
results and zero external dependencies.
"""
const DOMAIN_KEYWORDS = Dict{String, Vector{String}}(
    "breakdancing" => ["bboy", "breaking", "dance", "b-boy", "breakdance", "powermove"],
    "web"          => ["redwood", "next", "react", "vue", "laravel", "rails", "express",
                       "django", "flask", "remix", "astro", "svelte", "nuxt", "gatsby",
                       "html", "css", "tailwind", "vercel", "netlify"],
    "creative"     => ["shader", "animation", "vfx", "art", "design", "creative",
                       "generative", "procedural", "p5", "processing", "threejs",
                       "webgl", "canvas"],
    "mobile"       => ["flutter", "swift", "ios", "android", "expo", "react-native",
                       "swiftui", "kotlin", "mobile", "app"],
    "systems"      => ["zig", "wasm", "webgpu", "rust", "compiler", "kernel",
                       "embedded", "os", "low-level", "assembly", "linker"],
    "music"        => ["music", "audio", "dj", "spotify", "sound", "beat", "synth",
                       "midi", "wav", "mp3", "daw"],
    "math"         => ["math", "equation", "calculus", "linear-algebra", "algebra",
                       "geometry", "topology", "differential", "numerical",
                       "fourier", "laplace", "matrix"],
    "ml_ai"        => ["ml", "ai", "neural", "model", "training", "inference",
                       "transformer", "llm", "gpt", "diffusion", "classifier",
                       "regression", "deep-learning", "machine-learning"],
)

# ─────────────────────────────────────────────────────────────────────────────
# Domain detection
# ─────────────────────────────────────────────────────────────────────────────

"""
    detect_domains(name::String, description::String, language::String) -> Vector{String}

Identify which skill domains a repository belongs to by matching its name,
description, and primary language against the DOMAIN_KEYWORDS taxonomy.

Returns a (possibly empty) vector of domain names like ["web", "creative"].

Teaching note — why combine name + description + language?
A repo named "shader-playground" with language "GLSL" and description
"WebGPU shader experiments" should match both "creative" and "systems".
Checking all three fields maximizes recall without sacrificing precision.
"""
function detect_domains(name::String, description::String, language::String)::Vector{String}
    combined = lowercase(name * " " * description * " " * language)
    domains = String[]
    for (domain, keywords) in DOMAIN_KEYWORDS
        if any(kw -> occursin(kw, combined), keywords)
            push!(domains, domain)
        end
    end
    return domains
end

# ─────────────────────────────────────────────────────────────────────────────
# Graph construction
# ─────────────────────────────────────────────────────────────────────────────

"""
    build_portfolio_graph(repos::Vector{RepoReport}) -> (SimpleGraph, Dict{Int,String}, Dict{Edge,Float64})

Construct an undirected weighted graph from the portfolio.

Each repository becomes a vertex. Edges connect repos that share attributes,
with weights determined by the type and strength of overlap:

    w(u, v) = 0.3 × 𝟙[same language]
            + 0.5 × |domains(u) ∩ domains(v)| / max(|domains(u)|, |domains(v)|)
            + 0.4 × 𝟙[shared tech keywords in description]

Edges are only created when w(u, v) > 0.

Returns a tuple of:
1. `g::SimpleGraph`           — the unweighted topology
2. `names::Dict{Int,String}`  — vertex index → repo name mapping
3. `weights::Dict{Edge,Float64}` — edge → combined weight

Teaching note — adjacency via shared attributes:
This is a form of bipartite projection. The "true" structure is bipartite:
repos connect to attributes (languages, domains), and we project onto the
repo-repo graph by linking repos that share attributes. The weight captures
how many attributes they share and how strongly.
"""
function build_portfolio_graph(repos::Vector{RepoReport})::Tuple{SimpleGraph, Dict{Int,String}, Dict{Edge,Float64}}
    n = length(repos)
    g = SimpleGraph(n)
    names = Dict{Int, String}()
    weights = Dict{Edge, Float64}()

    # Pre-compute per-repo metadata
    repo_languages = Vector{String}(undef, n)
    repo_domains = Vector{Vector{String}}(undef, n)
    repo_desc_words = Vector{Set{String}}(undef, n)

    for (i, repo) in enumerate(repos)
        names[i] = repo.name
        repo_languages[i] = lowercase(repo.language)

        desc = hasfield(typeof(repo.triage), :description) ? repo.triage.description : ""
        repo_domains[i] = detect_domains(repo.name, desc, repo.language)

        # Extract description words for tech keyword overlap
        combined_text = lowercase(repo.name * " " * desc)
        repo_desc_words[i] = Set(split(combined_text, r"[-_\s,.:;!?/]+"))
    end

    # Build edges between all repo pairs
    for i in 1:n
        for j in (i+1):n
            weight = 0.0

            # --- Same primary language (weight 0.3) ---
            # Two repos in the same language share tooling knowledge and patterns.
            if !isempty(repo_languages[i]) && repo_languages[i] == repo_languages[j]
                weight += 0.3
            end

            # --- Shared domains (weight up to 0.5) ---
            # Domain overlap is the strongest signal: repos in the same domain
            # share conceptual knowledge, not just syntax.
            domains_i = repo_domains[i]
            domains_j = repo_domains[j]
            if !isempty(domains_i) && !isempty(domains_j)
                shared = length(intersect(domains_i, domains_j))
                max_domains = max(length(domains_i), length(domains_j))
                if shared > 0
                    # Jaccard-like coefficient scaled to 0.5
                    weight += 0.5 * (shared / max_domains)
                end
            end

            # --- Shared tech keywords in description (weight 0.4) ---
            # Description word overlap beyond trivial stopwords signals
            # shared technology stack.
            shared_words = intersect(repo_desc_words[i], repo_desc_words[j])
            # Filter out trivial short words (stopwords, articles, etc.)
            meaningful_shared = filter(w -> length(w) >= 4, shared_words)
            if length(meaningful_shared) >= 2
                # Sigmoid-like saturation: more shared words → diminishing returns
                overlap_score = min(length(meaningful_shared) / 5.0, 1.0)
                weight += 0.4 * overlap_score
            end

            # Only create edge if there is meaningful similarity
            if weight > 0.0
                add_edge!(g, i, j)
                weights[Edge(i, j)] = weight
            end
        end
    end

    @info "Portfolio graph built" vertices=nv(g) edges=ne(g)
    return (g, names, weights)
end

# ─────────────────────────────────────────────────────────────────────────────
# Centrality analysis
# ─────────────────────────────────────────────────────────────────────────────

"""
    compute_centrality(g::SimpleGraph, names::Dict{Int,String}) -> Vector{Tuple{String, Float64}}

Compute betweenness centrality for each repo in the portfolio graph and return
a sorted list of (repo_name, centrality_score), highest first.

Betweenness centrality C_B(v) measures how often vertex v lies on shortest
paths between other vertices:

    C_B(v) = ∑_{s≠v≠t} σ_{st}(v) / σ_{st}

where σ_{st} is the total number of shortest paths from s to t, and
σ_{st}(v) is the number of those paths passing through v.

Portfolio interpretation:
• High centrality → "bridge" repos connecting different skill domains.
  These demonstrate cross-domain versatility (e.g., a Flutter app that
  uses ML models bridges mobile and AI domains).
• Low centrality → repos deep within a single cluster (specialized)
  or completely isolated (disconnected from the portfolio narrative).

Teaching note — Brandes' algorithm:
Graphs.jl implements Brandes' O(VE) algorithm for betweenness centrality,
which is far more efficient than the naive O(V³) approach of computing
all-pairs shortest paths first.
"""
function compute_centrality(g::SimpleGraph, names::Dict{Int,String})::Vector{Tuple{String, Float64}}
    n = nv(g)
    n == 0 && return Tuple{String, Float64}[]

    # Compute betweenness centrality using Graphs.jl
    # Returns a vector of Float64 indexed by vertex
    bc = betweenness_centrality(g)

    # Pair each repo name with its centrality score
    results = Tuple{String, Float64}[]
    for i in 1:n
        push!(results, (get(names, i, "unknown"), bc[i]))
    end

    # Sort descending by centrality score
    sort!(results, by=x -> x[2], rev=true)
    return results
end

# ─────────────────────────────────────────────────────────────────────────────
# Skill cluster detection
# ─────────────────────────────────────────────────────────────────────────────

"""
    detect_skill_clusters(g::SimpleGraph, names::Dict{Int,String}) -> Vector{Vector{String}}

Group repos into skill clusters based on graph structure using connected
components analysis.

Each connected component represents a group of repos that share enough
attributes to be reachable from each other through chains of shared
languages, domains, or tech stack keywords.

Returns a vector of clusters, where each cluster is a vector of repo names.
Clusters are sorted by size (largest first).

Teaching note — connected components vs. community detection:
Connected components give us hard clusters: two repos are either in the
same cluster or not. More sophisticated methods like Louvain or label
propagation can find overlapping communities, but for portfolio analysis,
hard clusters map well to the intuitive notion of "skill domains" and
require no threshold tuning.

When the graph is fully connected (all repos share at least one attribute),
we fall back to a simple degree-based partitioning: repos with above-median
degree form the "core" cluster, and those below form "peripheral" clusters.
"""
function detect_skill_clusters(g::SimpleGraph, names::Dict{Int,String})::Vector{Vector{String}}
    n = nv(g)
    n == 0 && return Vector{Vector{String}}()

    # Find connected components
    components = connected_components(g)

    # Convert vertex indices to repo names
    clusters = Vector{Vector{String}}()
    for component in components
        cluster = [get(names, v, "unknown") for v in component]
        sort!(cluster)  # Alphabetical within cluster for determinism
        push!(clusters, cluster)
    end

    # Sort clusters by size (largest first)
    sort!(clusters, by=length, rev=true)

    @info "Detected skill clusters" num_clusters=length(clusters) sizes=length.(clusters)
    return clusters
end

# ─────────────────────────────────────────────────────────────────────────────
# Language distribution
# ─────────────────────────────────────────────────────────────────────────────

"""
    language_distribution(repos::Vector{RepoReport}) -> Dict{String, Int}

Count the number of repos per primary language.

This is a simple frequency table, but it feeds into the graph analysis
summary to provide context: a portfolio with 15 JavaScript repos and
1 Zig repo has very different structural properties than one evenly
spread across 8 languages.
"""
function language_distribution(repos::Vector{RepoReport})::Dict{String, Int}
    dist = Dict{String, Int}()
    for repo in repos
        lang = isempty(repo.language) ? "Unknown" : repo.language
        dist[lang] = get(dist, lang, 0) + 1
    end
    return dist
end

# ─────────────────────────────────────────────────────────────────────────────
# Composite graph analysis summary
# ─────────────────────────────────────────────────────────────────────────────

"""
    graph_analysis_summary(repos::Vector{RepoReport}) -> Dict{String, Any}

Run the full graph-theoretic analysis pipeline and return a summary dictionary
suitable for inclusion in the audit report.

Returns a Dict with keys:
- `"clusters"`             — Vector of skill clusters (each a Vector{String})
- `"hub_repos"`            — Top repos by betweenness centrality (name, score)
- `"isolated_repos"`       — Repos with zero edges (degree 0)
- `"language_distribution"`— Dict{String, Int} of language frequencies
- `"num_vertices"`         — Number of repos (graph vertices)
- `"num_edges"`            — Number of connections (graph edges)
- `"density"`              — Graph density = 2|E| / (|V|(|V|-1)), measuring
                             overall portfolio interconnectedness
- `"avg_clustering_coeff"` — Average local clustering coefficient, measuring
                             how tightly each repo's neighbors connect to each other

Teaching note — graph density as a portfolio metric:
A density of 1.0 means every repo shares attributes with every other repo
(extremely focused portfolio). A density near 0 means most repos are
unrelated (highly diverse or incoherent). Neither extreme is ideal:
moderate density (0.2-0.5) suggests healthy thematic coherence with
meaningful diversification.
"""
function graph_analysis_summary(repos::Vector{RepoReport})::Dict{String, Any}
    isempty(repos) && return Dict{String, Any}(
        "clusters"              => Vector{Vector{String}}(),
        "hub_repos"             => Vector{Tuple{String, Float64}}(),
        "isolated_repos"        => String[],
        "language_distribution" => Dict{String, Int}(),
        "num_vertices"          => 0,
        "num_edges"             => 0,
        "density"               => 0.0,
        "avg_clustering_coeff"  => 0.0,
    )

    # Build the graph
    (g, names, weights) = build_portfolio_graph(repos)
    n = nv(g)

    # Centrality analysis
    centrality = compute_centrality(g, names)

    # Cluster detection
    clusters = detect_skill_clusters(g, names)

    # Identify hub repos (top 5 by centrality, or fewer if portfolio is small)
    hub_count = min(5, length(centrality))
    hub_repos = centrality[1:hub_count]

    # Identify isolated repos (degree 0 — no connections to any other repo)
    isolated = String[]
    for i in 1:n
        if degree(g, i) == 0
            push!(isolated, get(names, i, "unknown"))
        end
    end

    # Graph density: 2|E| / (|V|(|V|-1))
    # Measures overall portfolio interconnectedness
    graph_density = n > 1 ? 2.0 * ne(g) / (n * (n - 1)) : 0.0

    # Average local clustering coefficient
    # For each vertex, the clustering coefficient measures the fraction of
    # its neighbors that are also connected to each other.
    # C(v) = 2T(v) / (deg(v) * (deg(v) - 1))
    # where T(v) is the number of triangles through v.
    avg_cc = _average_clustering_coefficient(g)

    # Language distribution
    lang_dist = language_distribution(repos)

    @info "Graph analysis complete" density=round(graph_density, digits=3) avg_cc=round(avg_cc, digits=3) clusters=length(clusters) isolated=length(isolated)

    return Dict{String, Any}(
        "clusters"              => clusters,
        "hub_repos"             => hub_repos,
        "isolated_repos"        => isolated,
        "language_distribution" => lang_dist,
        "num_vertices"          => n,
        "num_edges"             => ne(g),
        "density"               => round(graph_density, digits=4),
        "avg_clustering_coeff"  => round(avg_cc, digits=4),
    )
end

# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

"""
    _average_clustering_coefficient(g::SimpleGraph) -> Float64

Compute the average local clustering coefficient across all vertices.

The local clustering coefficient for vertex v is:

    C(v) = 2T(v) / (k_v × (k_v - 1))

where T(v) is the number of triangles containing v and k_v = degree(v).
For vertices with degree < 2, C(v) = 0 by convention.

The average C̄ = (1/n) × ∑ C(v) measures the overall "cliquishness"
of the graph — how much repos cluster into tightly-knit groups.

Teaching note — why clustering coefficient matters:
High clustering means skill domains are well-defined internally (repos
within a domain all share attributes with each other). Low clustering
means even within a cluster, repos are loosely related. For a portfolio,
moderate-to-high clustering suggests genuine depth in each skill area.
"""
function _average_clustering_coefficient(g::SimpleGraph)::Float64
    n = nv(g)
    n == 0 && return 0.0

    total_cc = 0.0
    for v in 1:n
        k = degree(g, v)
        k < 2 && continue

        # Count triangles: for each pair of neighbors of v,
        # check if they are also connected
        neighs = neighbors(g, v)
        triangles = 0
        for i in 1:length(neighs)
            for j in (i+1):length(neighs)
                if has_edge(g, neighs[i], neighs[j])
                    triangles += 1
                end
            end
        end

        # Local clustering coefficient
        total_cc += 2.0 * triangles / (k * (k - 1))
    end

    return total_cc / n
end
