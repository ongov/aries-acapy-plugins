"""Models for the tenant database."""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Integer,
    MetaData,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for declarative models."""

    metadata = MetaData()


class Client(Base):
    """OAuth2 client registration for issuer->tenant auth."""

    __tablename__ = "client"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    client_auth_method: Mapped[str] = mapped_column(Text, nullable=False)
    client_auth_signing_alg: Mapped[str | None] = mapped_column(Text, nullable=True)
    client_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    jwks: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    jwks_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True, onupdate=func.now()
    )


class Subject(Base):
    """Subject model."""

    __tablename__ = "subject"
    __table_args__ = (UniqueConstraint("uid", name="uq_subject_uid"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uid: Mapped[str] = mapped_column(Text, nullable=False)
    subject_metadata: Mapped[dict | None] = mapped_column(
        "metadata", JSONB, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True, onupdate=func.now()
    )
    pre_auth_codes: Mapped[list["PreAuthCode"]] = relationship(
        back_populates="subject", cascade="all, delete-orphan", lazy="selectin"
    )
    access_tokens: Mapped[list["AccessToken"]] = relationship(
        back_populates="subject", cascade="all, delete-orphan", lazy="selectin"
    )
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="subject", cascade="all, delete-orphan", lazy="selectin"
    )
    dpop_jtis: Mapped[list["DpopJti"]] = relationship(
        back_populates="subject", cascade="all, delete-orphan", lazy="selectin"
    )


class PreAuthCode(Base):
    """PreAuthCode model."""

    __tablename__ = "pre_auth_code"
    __table_args__ = (UniqueConstraint("code", name="uq_pre_auth_code_code"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    subject_id: Mapped[int] = mapped_column(
        ForeignKey("subject.id", onupdate="CASCADE", ondelete="CASCADE"), nullable=False
    )
    code: Mapped[str] = mapped_column(Text, nullable=False)
    user_pin: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_pin_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    authorization_details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    subject: Mapped["Subject"] = relationship(
        back_populates="pre_auth_codes", lazy="joined"
    )


class AccessToken(Base):
    """AccessToken model."""

    __tablename__ = "access_token"
    __table_args__ = (UniqueConstraint("token", name="uq_access_token_token"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    subject_id: Mapped[int] = mapped_column(
        ForeignKey("subject.id", onupdate="CASCADE", ondelete="CASCADE"), nullable=False
    )
    token: Mapped[str] = mapped_column(Text, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cnf_jkt: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_metadata: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)
    subject: Mapped["Subject"] = relationship(
        back_populates="access_tokens", lazy="joined"
    )
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="access_token", cascade="all, delete-orphan", lazy="selectin"
    )


class RefreshToken(Base):
    """RefreshToken model."""

    __tablename__ = "refresh_token"
    __table_args__ = (UniqueConstraint("token_hash", name="uq_refresh_token_hash"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    subject_id: Mapped[int] = mapped_column(
        ForeignKey("subject.id", onupdate="CASCADE", ondelete="CASCADE"), nullable=False
    )
    access_token_id: Mapped[int] = mapped_column(
        ForeignKey("access_token.id", onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    token_metadata: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)
    subject: Mapped["Subject"] = relationship(
        back_populates="refresh_tokens", lazy="joined"
    )
    access_token: Mapped["AccessToken"] = relationship(
        back_populates="refresh_tokens", lazy="joined"
    )


class DpopJti(Base):
    """DpopJti model."""

    __tablename__ = "dpop_jti"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    subject_id: Mapped[int] = mapped_column(
        ForeignKey("subject.id", onupdate="CASCADE", ondelete="CASCADE"), nullable=False
    )
    jti: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    htm: Mapped[str | None] = mapped_column(Text, nullable=True)
    htu: Mapped[str | None] = mapped_column(Text, nullable=True)
    cnf_jkt: Mapped[str | None] = mapped_column(Text, nullable=True)
    issued_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    subject: Mapped["Subject"] = relationship(back_populates="dpop_jtis", lazy="joined")
