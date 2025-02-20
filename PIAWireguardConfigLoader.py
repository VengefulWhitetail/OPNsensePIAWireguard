from abc import ABC, abstractmethod


class PIAWireguardConfigLoader(ABC):

	@abstractmethod
	def is_valid(self) -> bool:
		pass

	def load_config(self) -> str:
		pass
