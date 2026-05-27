import shutil
import tempfile
from pathlib import Path

from shoestring.wizard.setup_file_generator import (
	patch_shoestring_config,
	prepare_overrides_file,
	prepare_overrides_file_from_bootstrap,
	prepare_shoestring_config,
	prepare_shoestring_files,
	prepare_shoestring_files_from_bootstrap,
	try_prepare_rest_overrides_file
)
from shoestring.wizard.ShoestringOperation import ShoestringOperation, build_shoestring_command


async def dispatch_shoestring_command(screens, executor):
	"""Dispatches a shoestring command specified by screens to a specified (async) executor."""

	obligatory_settings = screens.get('obligatory')
	destination_directory = Path(obligatory_settings.destination_directory)
	shoestring_directory = destination_directory / 'shoestring'

	operation = screens.get('welcome').operation
	package = screens.get('network-type').current_value
	
	#==========network-typeを自動判別==========
	if ShoestringOperation.UPGRADE == operation:
		# 既存のshoestring.iniからnetworkを自動判別
		config_path = shoestring_directory / 'shoestring.ini'
		if not config_path.exists():
			# エラー処理（必要に応じて）
			raise FileNotFoundError(f"shoestring.ini not found at {config_path}")

		from shoestring.internal.ShoestringConfiguration import parse_shoestring_configuration
		config = parse_shoestring_configuration(config_path)
		package = config.network.name  # または config.network.get('name', 'mainnet')
		if package == "testnet":
			package = "sai"
		# === デバッグ用出力（ここを追加）===
		print(f"[DEBUG] UPGRADE mode: Detected network from shoestring.ini -> package = '{package}'")
		print(f"[DEBUG] Config path: {config_path}")
		# ===================================
	else:
		package = screens.get('network-type').current_value
	# ==================

	if ShoestringOperation.SETUP == operation:
		with tempfile.TemporaryDirectory() as temp_directory:
			has_custom_rest_overrides = try_prepare_rest_overrides_file(screens, Path(temp_directory) / 'rest_overrides.json')
			prepare_overrides_file(screens, Path(temp_directory) / 'overrides.ini')
			await prepare_shoestring_files(screens, Path(temp_directory))

			shoestring_args = build_shoestring_command(
				operation,
				destination_directory,
				temp_directory,
				obligatory_settings.ca_pem_path,
				package,
				has_custom_rest_overrides)
			await executor(shoestring_args)

			shoestring_directory.mkdir()
			for filename in ('shoestring.ini', 'overrides.ini', 'rest_overrides.json'):
				source_path = Path(temp_directory) / filename
				if source_path.exists():
					shutil.copy(source_path, shoestring_directory)
	elif ShoestringOperation.IMPORT_BOOTSTRAP == operation:
		shoestring_directory.mkdir()
		has_custom_rest_overrides = try_prepare_rest_overrides_file(screens, shoestring_directory / 'rest_overrides.json')
		prepare_overrides_file_from_bootstrap(screens, shoestring_directory / 'overrides.ini')
		await prepare_shoestring_files_from_bootstrap(screens, shoestring_directory)

		shoestring_args = build_shoestring_command(
			ShoestringOperation.SETUP,
			destination_directory,
			shoestring_directory,
			obligatory_settings.ca_pem_path,
			package,
			has_custom_rest_overrides)
		await executor(shoestring_args)
	else:
		if ShoestringOperation.UPGRADE == operation:
			with tempfile.TemporaryDirectory() as temp_directory:
				config_filepath = Path(temp_directory) / 'shoestring.ini'
				await prepare_shoestring_config(package, config_filepath)  # ← ここで自動取得したpackageを使う
				patch_shoestring_config(shoestring_directory / 'shoestring.ini', config_filepath)

		shoestring_args = build_shoestring_command(
			operation,
			destination_directory,
			shoestring_directory,
			obligatory_settings.ca_pem_path,
			package)
		await executor(shoestring_args)
