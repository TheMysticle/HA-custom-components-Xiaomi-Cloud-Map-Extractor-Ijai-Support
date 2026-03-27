import logging
from typing import Self
import zlib

from miio.miot_device import MiotDevice
from miio.exceptions import DeviceException

from vacuum_map_parser_base.map_data import MapData
from vacuum_map_parser_ijai.map_data_parser import IjaiMapDataParser
from vacuum_map_parser_ijai.status_mapping import get_status_mapping
from .base.vacuum_v2 import BaseXiaomiCloudVacuumV2
from .base.model import VacuumConfig, VacuumApi
from ..utils.exceptions import FailedConnectionException

_LOGGER = logging.getLogger(__name__)
OFF_UPDATES = 3


class IjaiCloudVacuum(BaseXiaomiCloudVacuumV2):
    WIFI_INFO_SN_LEN = 18

    def __init__(self, vacuum_config: VacuumConfig):
        super().__init__(vacuum_config)
        self._token = vacuum_config.token
        self._host = vacuum_config.host
        self._mac = vacuum_config.device_info.mac
        self._wifi_info_sn = None

        self._miot_device = MiotDevice(self._host, self._token, timeout=2)

        self._ijai_map_data_parser = IjaiMapDataParser(
            vacuum_config.palette,
            vacuum_config.sizes,
            vacuum_config.drawables,
            vacuum_config.image_config,
            vacuum_config.texts
        )

        self._status_mapping = get_status_mapping(self.model)
        self._off_counter = 0

    @property
    def should_update_map(self: Self) -> bool:
        try:
            status_value = self._miot_device.get_property_by(
                self._status_mapping.siid,
                self._status_mapping.piid
            )[0]["value"]

            if status_value in self._status_mapping.idle_at:
                self._off_counter += 1
                _LOGGER.debug("Vacuum is not moving. Off counter: %d", self._off_counter)
                return self._off_counter <= OFF_UPDATES
            else:
                self._off_counter = 0
                return True

        except DeviceException as de:
            if "token" not in repr(de):
                return False
            raise FailedConnectionException(de)

    @staticmethod
    def vacuum_platform() -> VacuumApi:
        return VacuumApi.IJAI

    @property
    def map_archive_extension(self) -> str:
        return "zlib.enc"

    @property
    def map_data_parser(self) -> IjaiMapDataParser:
        return self._ijai_map_data_parser

    async def get_map_url(self, map_name: str) -> str | None:
        if self.model == "ijai.vacuum.v3":
            url = self._connector.get_api_url(self._server) + '/v2/home/get_interim_file_url'
        else:
            url = self._connector.get_api_url(self._server) + '/v2/home/get_interim_file_url_pro'

        params = {
            "data": f'{{"obj_name":"{self._user_id}/{self._device_id}/{map_name}"}}'
        }

        api_response = await self._connector.execute_api_call_encrypted(url, params)

        if (
            api_response is None
            or "result" not in api_response
            or api_response["result"] is None
            or "url" not in api_response["result"]
        ):
            _LOGGER.debug(
                f"API returned {api_response.get('code', 'unknown')} ({api_response.get('message', '')})"
            )
            return None

        return api_response["result"]["url"]

    def get_wifi_info_sn(self):
        wifi_info_sn = None
        piids = [3, 5]

        for piid in piids:
            data = self._miot_device.get_property_by(1, piid)
            if (
                "value" in data[0]
                and len(data[0]["value"]) == self.WIFI_INFO_SN_LEN
                and data[0]["value"].isalnum()
                and data[0]["value"].isupper()
            ):
                wifi_info_sn = data[0]["value"]
                break

        if not wifi_info_sn:
            got_from_vacuum = self._miot_device.get_property_by(7, 45)

            for prop in got_from_vacuum[0]["value"].split(','):
                cleaned_prop = str(prop).replace('"', '')

                if str(self._user_id) in cleaned_prop:
                    cleaned_prop = cleaned_prop.split(';')[0]

                if (
                    len(cleaned_prop) == self.WIFI_INFO_SN_LEN
                    and cleaned_prop.isalnum()
                    and cleaned_prop.isupper()
                ):
                    wifi_info_sn = cleaned_prop

        _LOGGER.warning(
            "IJAI DEBUG wifi_info_sn=%s (len=%s)",
            wifi_info_sn,
            len(wifi_info_sn) if wifi_info_sn else None
        )

        return wifi_info_sn

    def decode_and_parse(self, raw_map: bytes) -> MapData:
        GET_PROP_RETRIES = 5

        if self._wifi_info_sn is None or self._wifi_info_sn == "":
            _LOGGER.warning(
                "IJAI DEBUG init: host=%s token=%s mac=%s model=%s user_id=%s device_id=%s",
                self._host,
                self._token,
                self._mac,
                self.model,
                self._user_id,
                self._device_id
            )

            for _ in range(GET_PROP_RETRIES):
                try:
                    self._wifi_info_sn = self.get_wifi_info_sn()
                    _LOGGER.warning(f"IJAI DEBUG Got wifi_sn={self._wifi_info_sn}")
                    break
                except Exception as ex:
                    _LOGGER.error("Failed to get wifi_sn from vacuum")
                    raise FailedConnectionException(ex)

        _LOGGER.warning(
            "IJAI DEBUG raw_map: len=%s mod16=%s first32=%s",
            len(raw_map) if raw_map else None,
            (len(raw_map) % 16) if raw_map else None,
            raw_map[:32].hex() if raw_map else None
        )

        _LOGGER.warning(
            "IJAI DEBUG keys: wifi_sn=%s user_id=%s device_id=%s model=%s mac=%s",
            self._wifi_info_sn,
            self._user_id,
            self._device_id,
            self.model,
            self._mac
        )

        # --- КЛЮЧЕВОЙ ФИКС ---
        if raw_map and raw_map[:2] == b'\x78\x9c':
            _LOGGER.warning("IJAI DEBUG detected zlib-compressed map, skipping AES")

            try:
                raw_map = zlib.decompress(raw_map)

                _LOGGER.warning(
                    "IJAI DEBUG after zlib: len=%s first32=%s",
                    len(raw_map),
                    raw_map[:32].hex()
                )

                # НЕ используем unpack_map → он делает AES
                return self.map_data_parser.parse(raw_map)

            except Exception as e:
                _LOGGER.error(f"zlib decompress failed: {e}")
                return None

        # fallback (старые модели с AES)
        decoded_map = self.map_data_parser.unpack_map(
            raw_map,
            wifi_sn=self._wifi_info_sn,
            owner_id=str(self._user_id),
            device_id=str(self._device_id),
            model=self.model,
            device_mac=self._mac
        )

        return self.map_data_parser.parse(decoded_map)
