# database/models.py

from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()


class ScanResult(Base):
    """main table to keep track of every scan we run"""
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_ip = Column(String, nullable=False)
    scan_time = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="completed")

    # one scan can find many services
    services = relationship("DiscoveredService", back_populates="scan")


class DiscoveredService(Base):
    """details about the services found on the target ip"""
    __tablename__ = "discovered_services"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scan_results.id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, default="tcp")
    service = Column(String)
    product = Column(String)
    version = Column(String)

    # connecting back to scan and linking vulnerabilities
    scan = relationship("ScanResult", back_populates="services")
    vulnerabilities = relationship("Vulnerability", back_populates="service")


class Vulnerability(Base):
    """matching cves for each service"""
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    service_id = Column(Integer, ForeignKey("discovered_services.id"), nullable=False)
    cve_id = Column(String, nullable=False)
    cvss_score = Column(Float)
    severity = Column(String)
    description = Column(String)

    service = relationship("DiscoveredService", back_populates="vulnerabilities")