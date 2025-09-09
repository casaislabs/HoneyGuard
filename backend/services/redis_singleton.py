import redis
from config import Config

class RedisService:
    def __init__(self):
        from utils.logger import get_logger  # Local import to avoid loops
        logger = get_logger(__name__)
        try:
            self.pool = redis.ConnectionPool(
                host=Config.REDIS_HOST,
                port=Config.REDIS_PORT,
                username=Config.REDIS_USERNAME,
                password=Config.REDIS_PASSWORD,
                decode_responses=True,
                socket_connect_timeout=5,
                max_connections=10
            )
            self.client = redis.Redis(connection_pool=self.pool)
            # Test connection
            self.client.ping()
            logger.info("Redis connection established successfully.")
        except Exception as e:
            logger.error(f"Error connecting to Redis: {e}")
            raise

    def get_client(self):
        return self.client

_redis_service = None
_redis_client = None

def get_redis_client():
    global _redis_service, _redis_client
    if _redis_client is None:
        _redis_service = RedisService()
        _redis_client = _redis_service.get_client()
    return _redis_client