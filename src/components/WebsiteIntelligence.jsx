import "./WebsiteIntelligence.css";
import { useState } from "react";
import {
  Activity,
  AlertCircle,
  ArrowUpRight,
  CalendarDays,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Database,
  Globe,
  HardDrive,
  LockKeyhole,
  MapPin,
  Network,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  ShieldAlert,
  Terminal,
} from "lucide-react";

const API_BASE =
  import.meta.env.VITE_INTELLIGENCE_API_URL || "http://127.0.0.1:5000";

const DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];

function formatDate(value) {
  if (!value) return "Not available";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return value;

  return date.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function StatusPill({ status }) {
  const good = status === "success" || status === "ok";

  return (
    <span className={`intel-status ${good ? "intel-status-good" : "intel-status-muted"}`}>
      <span />
      {good ? "Retrieved" : "Unavailable"}
    </span>
  );
}

function MetricCard({ icon: Icon, label, value, detail }) {
  return (
    <article className="intel-metric-card">
      <div className="intel-metric-icon">
        <Icon size={19} />
      </div>
      <span className="intel-metric-label">{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}

function SectionHeader({ icon: Icon, title, subtitle, status }) {
  return (
    <div className="intel-section-header">
      <div className="intel-section-title">
        <span className="intel-section-icon">
          <Icon size={19} />
        </span>
        <div>
          <h3>{title}</h3>
          <p>{subtitle}</p>
        </div>
      </div>
      {status && <StatusPill status={status} />}
    </div>
  );
}

function DataValue({ value }) {
  if (value === null || value === undefined || value === "") {
    return <span className="intel-muted">Not available</span>;
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  if (typeof value === "object") {
    return JSON.stringify(value);
  }

  return String(value);
}

function RecordList({ records }) {
  if (!records?.length) {
    return <p className="intel-empty-inline">No records returned for this type.</p>;
  }

  return (
    <ul className="intel-record-list">
      {records.map((record, index) => {
        const value =
          typeof record === "object"
            ? `${record.priority ?? ""} ${record.server ?? ""}`.trim()
            : record;

        return <li key={`${value}-${index}`}>{value}</li>;
      })}
    </ul>
  );
}

function DnsPanel({ dns }) {
  const [activeType, setActiveType] = useState("A");

  return (
    <section className="intel-panel">
      <SectionHeader
        icon={Network}
        title="DNS records"
        subtitle="Public records returned by DNS resolvers"
        status="success"
      />

      <div className="intel-dns-tabs" role="tablist" aria-label="DNS record type">
        {DNS_TYPES.map((type) => (
          <button
            key={type}
            type="button"
            role="tab"
            aria-selected={activeType === type}
            className={activeType === type ? "active" : ""}
            onClick={() => setActiveType(type)}
          >
            {type}
          </button>
        ))}
      </div>

      <div className="intel-dns-content">
        <div className="intel-dns-content-top">
          <strong>{activeType} records</strong>
          <span>{dns?.[activeType]?.records?.length ?? 0} returned</span>
        </div>

        {dns?.[activeType]?.status === "lookup_failed" ? (
          <p className="intel-empty-inline">
            The DNS lookup failed or timed out. Try again later.
          </p>
        ) : (
          <RecordList records={dns?.[activeType]?.records} />
        )}

        <p className="intel-source-note">
          Resolver status: {dns?.[activeType]?.status || "not available"}
        </p>
      </div>
    </section>
  );
}

function RegistrationPanel({ registration }) {
  const events = registration?.events || {};

  return (
    <section className="intel-panel">
      <SectionHeader
        icon={CalendarDays}
        title="Domain registration"
        subtitle="Public RDAP registration metadata"
        status={registration?.status}
      />

      {registration?.status === "success" ? (
        <>
          <div className="intel-detail-grid">
            <div className="intel-detail-item">
              <span>Registered domain</span>
              <strong>{registration.domain || "Not available"}</strong>
            </div>
            <div className="intel-detail-item">
              <span>Registration handle</span>
              <strong>{registration.handle || "Not provided"}</strong>
            </div>
            <div className="intel-detail-item">
              <span>Registration date</span>
              <strong>{formatDate(events.registration)}</strong>
            </div>
            <div className="intel-detail-item">
              <span>Last updated</span>
              <strong>{formatDate(events["last changed"] || events["last update of RDAP database"])}</strong>
            </div>
            <div className="intel-detail-item">
              <span>Expiration date</span>
              <strong>{formatDate(events.expiration)}</strong>
            </div>
            <div className="intel-detail-item">
              <span>DNSSEC</span>
              <strong>
                {registration.secure_dns?.delegationSigned === true
                  ? "Signed"
                  : registration.secure_dns?.delegationSigned === false
                    ? "Not signed"
                    : "Not reported"}
              </strong>
            </div>
          </div>

          {registration.nameservers?.length > 0 && (
            <div className="intel-subsection">
              <h4>Nameservers</h4>
              <RecordList records={registration.nameservers} />
            </div>
          )}

          {registration.registrar_entities?.length > 0 && (
            <div className="intel-subsection">
              <h4>Registration entities</h4>
              <RecordList
                records={registration.registrar_entities.map(
                  (entity) =>
                    `${entity.name || "Entity"}${
                      entity.roles?.length ? ` — ${entity.roles.join(", ")}` : ""
                    }`
                )}
              />
            </div>
          )}

          <p className="intel-source-note">
            Source: {registration.source || "RDAP"}. Registrant details may be
            redacted or unavailable.
          </p>
        </>
      ) : (
        <p className="intel-empty-inline">
          {registration?.message || "Registration information was not returned."}
        </p>
      )}
    </section>
  );
}

function IpPanel({ addresses, intelligence }) {
  const ips = [
    ...(addresses?.ipv4 || []),
    ...(addresses?.ipv6 || []),
  ];

  return (
    <section className="intel-panel">
      <SectionHeader
        icon={Server}
        title="IP & hosting intelligence"
        subtitle="Resolved public IP addresses and network metadata"
        status={ips.length ? "success" : "unavailable"}
      />

      <div className="intel-ip-list">
        {ips.length === 0 ? (
          <p className="intel-empty-inline">
            No public IP addresses were returned. DNS may be unavailable.
          </p>
        ) : (
          ips.map((ip) => {
            const info = intelligence?.find((item) => item.ip === ip);

            return (
              <article className="intel-ip-card" key={ip}>
                <div className="intel-ip-heading">
                  <span className="intel-ip-icon">
                    <HardDrive size={18} />
                  </span>
                  <div>
                    <strong>{ip}</strong>
                    <small>{ip.includes(":") ? "IPv6 address" : "IPv4 address"}</small>
                  </div>
                  <button
                    type="button"
                    className="intel-copy-button"
                    onClick={() => navigator.clipboard?.writeText(ip)}
                    aria-label={`Copy IP address ${ip}`}
                  >
                    Copy
                  </button>
                </div>

                <div className="intel-detail-grid">
                  <div className="intel-detail-item">
                    <span>Organization</span>
                    <strong><DataValue value={info?.organization || info?.isp} /></strong>
                  </div>
                  <div className="intel-detail-item">
                    <span>ASN</span>
                    <strong><DataValue value={info?.asn} /></strong>
                  </div>
                  <div className="intel-detail-item">
                    <span>Location</span>
                    <strong>
                      {info?.status === "success"
                        ? [info.city, info.region, info.country].filter(Boolean).join(", ") || "Not reported"
                        : "Not reported"}
                    </strong>
                  </div>
                  <div className="intel-detail-item">
                    <span>Metadata source</span>
                    <strong>{info?.source || "Not available"}</strong>
                  </div>
                </div>

                {info?.latitude != null && info?.longitude != null && (
                  <a
                    className="intel-external-link"
                    href={`https://www.openstreetmap.org/?mlat=${encodeURIComponent(info.latitude)}&mlon=${encodeURIComponent(info.longitude)}#map=8/${encodeURIComponent(info.latitude)}/${encodeURIComponent(info.longitude)}`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    View approximate area <ArrowUpRight size={14} />
                  </a>
                )}
              </article>
            );
          })
        )}
      </div>

      <p className="intel-source-note">
        Geolocation is approximate. An IP may belong to a CDN or proxy rather
        than the origin server.
      </p>
    </section>
  );
}

function TlsPanel({ tls }) {
  const valid = tls?.status === "success" && tls.expired === false;

  return (
    <section className="intel-panel">
      <SectionHeader
        icon={LockKeyhole}
        title="TLS / SSL certificate"
        subtitle="Certificate details from a TLS handshake"
        status={tls?.status}
      />

      {tls?.status === "success" ? (
        <>
          <div className={`intel-tls-banner ${valid ? "tls-valid" : "tls-warning"}`}>
            {valid ? <CheckCircle2 size={21} /> : <ShieldAlert size={21} />}
            <div>
              <strong>{valid ? "Certificate is currently within its validity period" : "Certificate validity needs attention"}</strong>
              <p>
                This checks certificate validity dates. It is not a complete
                website security assessment.
              </p>
            </div>
          </div>

          <div className="intel-detail-grid">
            <div className="intel-detail-item">
              <span>Subject</span>
              <strong>{tls.subject || "Not reported"}</strong>
            </div>
            <div className="intel-detail-item">
              <span>Issuer</span>
              <strong>{tls.issuer || "Not reported"}</strong>
            </div>
            <div className="intel-detail-item">
              <span>Valid from</span>
              <strong>{formatDate(tls.valid_from)}</strong>
            </div>
            <div className="intel-detail-item">
              <span>Valid until</span>
              <strong>{formatDate(tls.valid_until)}</strong>
            </div>
          </div>

          {tls.subject_alt_names?.length > 0 && (
            <div className="intel-subsection">
              <h4>Certificate DNS names</h4>
              <RecordList records={tls.subject_alt_names} />
            </div>
          )}
        </>
      ) : (
        <p className="intel-empty-inline">
          {tls?.message || "Certificate information could not be retrieved."}
        </p>
      )}
    </section>
  );
}

export default function WebsiteIntelligence() {
  const [domainInput, setDomainInput] = useState("");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [lastChecked, setLastChecked] = useState(null);

  async function runLookup(event) {
    event.preventDefault();
    setError("");
    setData(null);
    setLastChecked(null);

    const value = domainInput.trim();

    if (!value) {
      setError("Enter a website domain to begin reconnaissance.");
      return;
    }

    setLoading(true);

    try {
      const endpoint = `${API_BASE.replace(/\/$/, "")}/api/intelligence?domain=${encodeURIComponent(value)}`;
      const response = await fetch(endpoint, {
        headers: { Accept: "application/json" },
      });

      const result = await response.json();

      if (!response.ok || result.status !== "success") {
        throw new Error(result.message || "The intelligence lookup failed.");
      }

      setData(result);
      setLastChecked(new Date());
    } catch (lookupError) {
      setError(
        lookupError instanceof Error
          ? `${lookupError.message} Make sure the Flask backend is running.`
          : "Unable to connect to the intelligence service."
      );
    } finally {
      setLoading(false);
    }
  }

  const ipv4Count = data?.ip_addresses?.ipv4?.length || 0;
  const ipv6Count = data?.ip_addresses?.ipv6?.length || 0;
  const dnsCount = DNS_TYPES.reduce(
    (total, type) => total + (data?.dns?.[type]?.records?.length || 0),
    0
  );

  return (
    <section className="website-intelligence section-container" id="intelligence">
      <div className="intel-hero">
        <div className="intel-hero-copy">
          <div className="intel-eyebrow">
            <span />
            RECONNAISSANCE WORKSPACE
          </div>
          <h2>
            Understand the domain.
            <br />
            <span>Map the public footprint.</span>
          </h2>
          <p>
            Collect publicly available DNS, registration, IP network and TLS
            certificate information in one readable report.
          </p>
        </div>
        <div className="intel-hero-symbol" aria-hidden="true">
          <Globe size={56} strokeWidth={1.1} />
          <span><Activity size={19} /></span>
        </div>
      </div>

      <form className="intel-search-panel" onSubmit={runLookup}>
        <div className="intel-search-label">
          <Terminal size={16} />
          <label htmlFor="intel-domain">TARGET DOMAIN</label>
          <span>PUBLIC INFORMATION ONLY</span>
        </div>

        <div className="intel-search-row">
          <div className="intel-input-wrap">
            <Search size={19} />
            <input
              id="intel-domain"
              type="text"
              value={domainInput}
              onChange={(event) => setDomainInput(event.target.value)}
              placeholder="example.com or https://example.com"
              autoComplete="url"
              maxLength={2048}
              disabled={loading}
            />
          </div>
          <button type="submit" className="intel-run-button" disabled={loading}>
            {loading ? <RefreshCw size={17} className="intel-spin" /> : <Search size={17} />}
            {loading ? "Gathering data..." : "Run intelligence"}
          </button>
        </div>

        <div className="intel-search-footer">
          <span><LockKeyhole size={14} /> Enter a public domain you are authorized to investigate.</span>
          <button type="button" onClick={() => setDomainInput("example.com")} disabled={loading}>
            Try example.com
          </button>
        </div>
      </form>

      {error && (
        <div className="intel-error" role="alert">
          <AlertCircle size={19} />
          <div>
            <strong>Lookup could not be completed</strong>
            <p>{error}</p>
          </div>
        </div>
      )}

      {loading && (
        <div className="intel-loading-panel" role="status" aria-live="polite">
          <div className="intel-loading-orbit"><Globe size={28} /></div>
          <strong>Collecting public domain intelligence</strong>
          <p>Querying DNS, registration metadata, IP information and TLS.</p>
          <div className="intel-loading-track"><span /></div>
          <small>Some sources may respond slowly or return incomplete data.</small>
        </div>
      )}

      {data && (
        <div className="intel-report">
          <div className="intel-report-heading">
            <div>
              <span className="intel-report-overline"><CheckCircle2 size={15} /> LOOKUP COMPLETE</span>
              <h3>{data.domain}</h3>
              <p>Public intelligence snapshot · {formatDate(data.checked_at)}</p>
            </div>
            <button
              type="button"
              className="intel-refresh-button"
              onClick={runLookup}
              disabled={loading}
              title="Run lookup again"
            >
              <RefreshCw size={16} /> Refresh
            </button>
          </div>

          <div className="intel-metrics-grid">
            <MetricCard
              icon={Globe}
              label="DOMAIN"
              value={data.domain}
              detail="Normalized hostname"
            />
            <MetricCard
              icon={HardDrive}
              label="PUBLIC IPs"
              value={ipv4Count + ipv6Count}
              detail={`${ipv4Count} IPv4 · ${ipv6Count} IPv6`}
            />
            <MetricCard
              icon={Database}
              label="DNS RECORDS"
              value={dnsCount}
              detail="Records returned"
            />
            <MetricCard
              icon={ShieldCheck}
              label="TLS CHECK"
              value={data.tls?.status === "success" ? data.tls.expired ? "Expired" : "Retrieved" : "Unavailable"}
              detail="Certificate date check"
            />
          </div>

          <div className="intel-report-grid">
            <div className="intel-report-main">
              <IpPanel addresses={data.ip_addresses} intelligence={data.ip_intelligence} />
              <DnsPanel dns={data.dns} />
              <RegistrationPanel registration={data.registration} />
              <TlsPanel tls={data.tls} />
            </div>

            <aside className="intel-report-sidebar">
              <section className="intel-panel intel-side-panel">
                <SectionHeader
                  icon={Activity}
                  title="Collection status"
                  subtitle="Result availability by source"
                />
                {[
                  ["DNS lookups", data.dns ? "success" : "unavailable"],
                  ["IP resolution", ipv4Count + ipv6Count ? "success" : "unavailable"],
                  ["RDAP", data.registration?.status],
                  ["TLS handshake", data.tls?.status],
                ].map(([label, status]) => (
                  <div className="intel-source-row" key={label}>
                    <span>{label}</span>
                    <StatusPill status={status} />
                  </div>
                ))}
                <div className="intel-side-divider" />
                <div className="intel-last-checked">
                  <Clock3 size={15} />
                  <span>Viewed {lastChecked ? lastChecked.toLocaleTimeString() : "just now"}</span>
                </div>
              </section>

              <section className="intel-panel intel-note-panel">
                <ShieldAlert size={22} />
                <h4>Interpret findings carefully</h4>
                <p>
                  Public metadata describes a domain's visible infrastructure.
                  It does not prove the site is trustworthy or malicious.
                </p>
              </section>

              <section className="intel-panel intel-note-panel">
                <MapPin size={22} />
                <h4>Location is approximate</h4>
                <p>
                  Network locations generally identify an IP registration or
                  hosting region, not an individual's physical location.
                </p>
              </section>
            </aside>
          </div>

          {data.limitations?.length > 0 && (
            <section className="intel-limitations">
              <ChevronDown size={17} />
              <div>
                <strong>Scope and limitations</strong>
                <ul>
                  {data.limitations.map((limitation) => (
                    <li key={limitation}>{limitation}</li>
                  ))}
                </ul>
              </div>
            </section>
          )}
        </div>
      )}
    </section>
  );
}
