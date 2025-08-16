package statusphere

type Status struct {
	URI       string
	Did       string
	Status    string
	CreatedAt int64
	IndexedAt int64
}

type CreateRecordResp struct {
	URI     string `json:"uri"`
	ErrStr  string `json:"error"`
	Message string `json:"message"`
}
