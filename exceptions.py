class SecurityEngineException(Exception):
    """Base exception for all custom exceptions"""
    pass

class ConfigurationError(SecurityEngineException):
    """Raised when configuration is invalid"""
    pass

class IngestionError(SecurityEngineException):
    """Raised when data ingestion fails"""
    pass

class DetectionError(SecurityEngineException):
    """Raised when detection processing fails"""
    pass

class EnrichmentError(SecurityEngineException):
    """Raised when enrichment fails"""
    pass

class RateLimitError(SecurityEngineException):
    """Raised when API rate limits are hit"""
    pass
    
 
