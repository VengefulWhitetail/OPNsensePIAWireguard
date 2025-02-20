import os.path
from PIAWireguardConfigLoader import PIAWireguardConfigLoader


class PIAWireguardConfigFileLoader(PIAWireguardConfigLoader):
	def __init__(self, path: str):
		self.path = path

	def is_valid(self) -> bool:
		return os.path.isfile(self.path)

	def load_config(self) -> str:
		with open(self.path, 'r') as f:
			return f.read()
