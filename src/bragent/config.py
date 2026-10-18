from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    falkor_host: str = "localhost"
    falkor_port: int = 6380
    graph_name: str = "iam"
    anthropic_api_key: str = ""
    model: str = "claude-opus-5-5"
    max_hops: int = 6
    audit_dir: str = "audit"

    # severity formula weights (docs/05)
    w_sens: float = 3
    w_ext: float = 2
    w_prox: float = 2
    ext_cap: int = 10
    prox_max_hops: int = 8


settings = Settings()
