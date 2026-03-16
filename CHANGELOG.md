# Changelog

## [2.0] - 2026-03-16

### Added
- **SOC Pipeline v2 - Mejorado** - Complete workflow redesign
- Dual LLM analysis with Qwen2.5 (Junior) and DeepSeek R1 (Senior)
- Dynamic risk scoring algorithm
- Multi-source threat intelligence enrichment
  - AbuseIPDB integration
  - GreyNoise integration
  - VirusTotal integration
- Internal enrichment with asset inventory and VIP user lookup
- Duplicate alert detection with MD5 hashing
- Telegram critical alert notifications
- Event memory and historical correlation
- Comprehensive metrics collection

### Changed
- Refactored alert processing pipeline for better performance
- Improved error handling and logging
- Enhanced documentation with architecture diagrams

### Fixed
- Alert deduplication issues
- IP classification logic
- Response parsing from LLM models

## [1.0] - 2025-12-01

### Added
- Initial SOC automation pipeline
- QRadar SIEM integration
- Basic alert filtering and processing
- Database storage for alerts
- n8n workflow engine setup
- Ollama local LLM integration
