package beaconeye

type ScanConfig struct {
	threads int
}

type ScanConfigOption func(*ScanConfig)

func NewScanConfig(opts ...ScanConfigOption) *ScanConfig {
	scanConfig := new(ScanConfig)
	for _, opt := range opts {
		opt(scanConfig)
	}

	return scanConfig
}

func WithThreads(threads int) ScanConfigOption {
	return func(scanConfig *ScanConfig) {
		scanConfig.threads = threads
	}
}
