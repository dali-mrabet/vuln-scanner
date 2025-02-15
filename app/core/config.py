from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str
    SCANNER_ENDPOINT: str

    class Config:
        case_sensitive = True
        env_file = ".env"


settings = Settings()
