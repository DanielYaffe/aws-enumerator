package common

type Edge struct {
	Start      EdgeQuery      `json:"start"`
	End        EdgeQuery      `json:"end"`
	Kind       string         `json:"kind"`
	Properties map[string]any `json:"properties,omitempty"`
}

type EdgeQuery struct {
	MatchBy string `json:"match_by,omitempty"`
	Value   string `json:"value"`
	Kind    string `json:"kind,omitempty"`
}

type Node struct {
	Id         string         `json:"id"`
	Kinds      []string       `json:"kinds"`
	Properties map[string]any `json:"properties"`
}

type OpenGraphFormat struct {
	Graph struct {
		Nodes []Node `json:"nodes"`
		Edges []Edge `json:"edges"`
	} `json:"graph"`
	Metadata struct {
		Sourcekind string `json:"source_kind"`
	} `json:"metadata"`
}
