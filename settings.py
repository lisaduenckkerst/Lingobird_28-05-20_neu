import os
from sqla_wrapper import SQLAlchemy

# connect to a database
# get env var named "DATABASE_URL" (PostgreSQL database on Heroku). If it doesn't exist, use sqlite database instead.
from sqlalchemy import create_engine

db = SQLAlchemy(os.getenv("DATABASE_URL", "sqlite:///db.lingobird.sqlite"))

# from sqlalchemy.pool import StaticPool

# engine = create_engine('sqlite://',
#                    connect_args={'check_same_thread': False},
#                    poolclass=StaticPool)
