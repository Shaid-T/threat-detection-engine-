import asyncio                 # lets us run async tasks
from abc import ABC, abstractmethod  # abstract base class, enforce methods in child classes
from typing import List, Dict, Any, Optional
import structlog               # structured logging
from datetime import datetime, timedelta
from collections import defaultdict  # dict that auto-creates default values
import signal                  # handle OS signals like Ctrl+C

logger = structlog.get_logger()  # structured logger instance

class BaseEngine(ABC):
    """Abstract base class for any engine component"""

    def __init__(self, name: str, config: dict = None):
        self.name = name                    # engine name
        self.config = config or {}          # config dict, default empty
        self.stats = defaultdict(int)       # stats counter, auto 0
        self.start_time = datetime.utcnow() # track start time
        self.is_running = False             # running state
        self._tasks = []                    # list of async tasks

    async def start(self):
        logger.info(f"Starting {self.name}")  # log start
        self.is_running = True                 # mark running

        # handle graceful shutdown signals
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self._handle_signal)

        try:
            await self._start()                # run component-specific start
            logger.info(f"{self.name} started successfully")
        except Exception as e:
            logger.error(f"Failed to start {self.name}", error=str(e))
            raise

    async def stop(self):
        logger.info(f"Stopping {self.name}")   # log stop
        self.is_running = False                 # mark stopped

        # cancel all running tasks
        for task in self._tasks:
            task.cancel()

        if self._tasks:
            # run all tasks, if one fails keep the others running
            await asyncio.gather(*self._tasks, return_exceptions=True)

        await self._stop()                      # run component-specific stop
        logger.info(f"{self.name} stopped")

    def _handle_signal(self, signum, frame):
        """Handle OS shutdown signals"""
        logger.info(f"Received signal {signum}, initiating shutdown")
        # schedule stop asynchronously
        asyncio.create_task(self.stop())

    @abstractmethod
    async def _start(self):
        """To be implemented by child: start logic"""
        pass

    @abstractmethod
    async def _stop(self):
        """To be implemented by child: stop logic"""
        pass

    def get_stats(self) -> Dict[str, Any]:
        """Return engine stats"""
        uptime = datetime.utcnow() - self.start_time
        return {
            'name': self.name,
            'uptime_seconds': uptime.total_seconds(),  # total runtime
            'is_running': self.is_running,            # running state
            **dict(self.stats)                         # include stats counters
        }
#######################################################################################3

			
