// OSINT Reconnaissance Automation Tool - Dashboard behaviour.
// Vanilla JavaScript only (no framework). Handles: running the scan,
// showing a loading indicator, populating each module's card with
// its own independent status/data, computing the OSINT Summary card,
// paginating large subdomain lists, and revealing the report
// download buttons once the scan completes.

document.addEventListener("DOMContentLoaded", function () {
    const startBtn = document.getElementById("start-recon-btn");
    const domainInput = document.getElementById("domain");

    const loadingIndicator = document.getElementById("loading-indicator");
    const loadingText = document.getElementById("loading-text");
    const scanMessage = document.getElementById("scan-message");

    const downloadButtons = document.getElementById("download-buttons");
    const downloadHtmlBtn = document.getElementById("download-html-btn");
    const downloadPdfBtn = document.getElementById("download-pdf-btn");

    const dashboard = document.getElementById("dashboard");

    // ---- Element references, grouped by card -------------------------

    const whois = {
        badge: document.getElementById("whois-status-badge"),
        message: document.getElementById("whois-message"),
        table: document.getElementById("whois-table"),
        fields: {
            registrar: document.getElementById("res-registrar"),
            creation_date: document.getElementById("res-creation-date"),
            expiry_date: document.getElementById("res-expiry-date"),
            organization: document.getElementById("res-organization"),
            country: document.getElementById("res-country"),
        },
        nameServersList: document.getElementById("res-name-servers"),
    };

    const dns = {
        badge: document.getElementById("dns-status-badge"),
        message: document.getElementById("dns-message"),
        table: document.getElementById("dns-table"),
        fields: {
            A: document.getElementById("res-dns-a"),
            AAAA: document.getElementById("res-dns-aaaa"),
            MX: document.getElementById("res-dns-mx"),
            TXT: document.getElementById("res-dns-txt"),
            NS: document.getElementById("res-dns-ns"),
            CNAME: document.getElementById("res-dns-cname"),
            SOA: document.getElementById("res-dns-soa"),
        },
    };

    const ssl = {
        badge: document.getElementById("ssl-status-badge"),
        message: document.getElementById("ssl-message"),
        table: document.getElementById("ssl-table"),
        fields: {
            common_name: document.getElementById("res-ssl-common-name"),
            issuer: document.getElementById("res-ssl-issuer"),
            valid_from: document.getElementById("res-ssl-valid-from"),
            valid_until: document.getElementById("res-ssl-valid-until"),
        },
    };

    const shodan = {
        badge: document.getElementById("shodan-status-badge"),
        message: document.getElementById("shodan-message"),
        table: document.getElementById("shodan-table"),
        fields: {
            ip: document.getElementById("res-shodan-ip"),
            isp: document.getElementById("res-shodan-isp"),
            organization: document.getElementById("res-shodan-organization"),
            open_ports: document.getElementById("res-shodan-open-ports"),
            operating_system: document.getElementById("res-shodan-os"),
        },
    };

    const email = {
        badge: document.getElementById("email-status-badge"),
        message: document.getElementById("email-message"),
        countLine: document.getElementById("email-count-line"),
        list: document.getElementById("res-emails"),
    };

    const social = {
        badge: document.getElementById("social-status-badge"),
        message: document.getElementById("social-message"),
        list: document.getElementById("social-links-list"),
        links: {
            linkedin: document.getElementById("res-social-linkedin"),
            github: document.getElementById("res-social-github"),
            twitter: document.getElementById("res-social-twitter"),
            facebook: document.getElementById("res-social-facebook"),
        },
    };

    const subdomain = {
        badge: document.getElementById("subdomain-status-badge"),
        message: document.getElementById("subdomain-message"),
        countLine: document.getElementById("subdomain-count-line"),
        list: document.getElementById("res-subdomains"),
        pagination: document.getElementById("subdomain-pagination"),
        prevBtn: document.getElementById("subdomain-prev-btn"),
        nextBtn: document.getElementById("subdomain-next-btn"),
        pageIndicator: document.getElementById("subdomain-page-indicator"),
    };

    const summary = {
        domain: document.getElementById("sum-domain"),
        ip: document.getElementById("sum-ip"),
        registrar: document.getElementById("sum-registrar"),
        country: document.getElementById("sum-country"),
        sslStatus: document.getElementById("sum-ssl-status"),
        shodanStatus: document.getElementById("sum-shodan-status"),
        subdomainCount: document.getElementById("sum-subdomain-count"),
        emailCount: document.getElementById("sum-email-count"),
    };

    // Subdomain pagination state
    const PAGE_SIZE = 50;
    let subdomainItems = [];
    let subdomainPage = 0;

    // ---- Small helpers -------------------------------------------------

    function formatValue(value) {
        if (Array.isArray(value)) {
            return value.length ? value.join(", ") : "Not Found";
        }
        if (value === null || value === undefined || value === "") {
            return "Not Found";
        }
        return String(value);
    }

    function setCardStatus(badgeEl, type, label) {
        badgeEl.textContent = label;
        badgeEl.className = "status-badge status-" + type;
    }

    function showMessage(messageEl, text) {
        messageEl.textContent = text;
        messageEl.hidden = false;
    }

    function hideMessage(messageEl) {
        messageEl.hidden = true;
        messageEl.textContent = "";
    }

    function postDomain(endpoint, domainValue) {
        const formData = new FormData();
        formData.append("domain", domainValue);
        return fetch(endpoint, { method: "POST", body: formData })
            .then((response) => response.json())
            .catch(() => ({
                status: "error",
                message: "Could not reach the server for this module.",
            }));
    }

    // Renders a DNS field's value; long values (e.g. SPF/DMARC TXT
    // records) get a wrapped, scrollable block instead of stretching
    // the table and breaking the layout.
    function renderDnsValue(tdEl, value) {
        const text = formatValue(value);
        tdEl.innerHTML = "";
        if (text.length > 60) {
            const pre = document.createElement("pre");
            pre.className = "dns-scroll-block";
            pre.textContent = text;
            tdEl.appendChild(pre);
        } else {
            tdEl.textContent = text;
        }
    }

    // Renders WHOIS name servers as a clean vertical list instead of
    // one long comma-separated paragraph.
    function renderNameServers(listEl, value) {
        listEl.innerHTML = "";
        const text = formatValue(value);
        if (text === "Not Found") {
            const li = document.createElement("li");
            li.textContent = "Not Found";
            listEl.appendChild(li);
            return;
        }
        text.split(",").forEach((server) => {
            const trimmed = server.trim();
            if (!trimmed) return;
            const li = document.createElement("li");
            li.textContent = trimmed;
            listEl.appendChild(li);
        });
    }

    function renderSimpleList(listEl, items) {
        listEl.innerHTML = "";
        items.forEach((item) => {
            const li = document.createElement("li");
            li.textContent = item;
            listEl.appendChild(li);
        });
    }

    // ---- Subdomain pagination -------------------------------------------

    function renderSubdomainPage() {
        const start = subdomainPage * PAGE_SIZE;
        const end = start + PAGE_SIZE;
        const pageItems = subdomainItems.slice(start, end);
        renderSimpleList(subdomain.list, pageItems);

        const totalPages = Math.max(1, Math.ceil(subdomainItems.length / PAGE_SIZE));
        subdomain.pageIndicator.textContent = `Page ${subdomainPage + 1} of ${totalPages}`;
        subdomain.prevBtn.disabled = subdomainPage === 0;
        subdomain.nextBtn.disabled = subdomainPage >= totalPages - 1;
        subdomain.pagination.hidden = subdomainItems.length <= PAGE_SIZE;
    }

    subdomain.prevBtn.addEventListener("click", function () {
        if (subdomainPage > 0) {
            subdomainPage -= 1;
            renderSubdomainPage();
        }
    });

    subdomain.nextBtn.addEventListener("click", function () {
        const totalPages = Math.max(1, Math.ceil(subdomainItems.length / PAGE_SIZE));
        if (subdomainPage < totalPages - 1) {
            subdomainPage += 1;
            renderSubdomainPage();
        }
    });

    // ---- Per-module runners ---------------------------------------------
    // Each runner updates its own card independently: a failure in one
    // module never blocks or affects the others.

    function runWhois(domainValue) {
        return postDomain("/whois", domainValue).then((data) => {
            if (data.status === "success") {
                Object.keys(whois.fields).forEach((key) => {
                    whois.fields[key].textContent = formatValue(data.data[key]);
                });
                renderNameServers(whois.nameServersList, data.data.name_servers);
                hideMessage(whois.message);
                whois.table.hidden = false;
                setCardStatus(whois.badge, "ok", "OK");
            } else {
                whois.table.hidden = true;
                showMessage(whois.message, data.message || "WHOIS lookup unavailable.");
                setCardStatus(whois.badge, "error", "Error");
            }
            return data;
        });
    }

    function runDns(domainValue) {
        return postDomain("/dns", domainValue).then((data) => {
            if (data.status === "success") {
                Object.keys(dns.fields).forEach((key) => {
                    renderDnsValue(dns.fields[key], data.data[key]);
                });
                hideMessage(dns.message);
                dns.table.hidden = false;
                setCardStatus(dns.badge, "ok", "OK");
            } else {
                dns.table.hidden = true;
                showMessage(dns.message, data.message || "DNS lookup unavailable.");
                setCardStatus(dns.badge, "error", "Error");
            }
            return data;
        });
    }

    function runSsl(domainValue) {
        return postDomain("/ssl", domainValue).then((data) => {
            if (data.status === "success") {
                Object.keys(ssl.fields).forEach((key) => {
                    ssl.fields[key].textContent = formatValue(data.data[key]);
                });
                hideMessage(ssl.message);
                ssl.table.hidden = false;
                if (data.data.common_name === "Not Found") {
                    setCardStatus(ssl.badge, "empty", "No Certificate");
                } else {
                    setCardStatus(ssl.badge, "ok", "OK");
                }
            } else {
                ssl.table.hidden = true;
                showMessage(ssl.message, data.message || "SSL information unavailable");
                setCardStatus(ssl.badge, "error", "Error");
            }
            return data;
        });
    }

    function runShodan(domainValue) {
        return postDomain("/shodan", domainValue).then((data) => {
            if (data.status === "success") {
                Object.keys(shodan.fields).forEach((key) => {
                    shodan.fields[key].textContent = formatValue(data.data[key]);
                });
                hideMessage(shodan.message);
                shodan.table.hidden = false;
                setCardStatus(shodan.badge, "ok", "OK");
            } else {
                shodan.table.hidden = true;
                showMessage(shodan.message, data.message || "Shodan lookup unavailable.");
                setCardStatus(shodan.badge, "error", "Error");
            }
            return data;
        });
    }

    function runEmail(domainValue) {
        return postDomain("/email", domainValue).then((data) => {
            if (data.status === "success") {
                const emails = data.data.emails || [];
                hideMessage(email.message);
                if (emails.length > 0) {
                    email.countLine.textContent = `Total found: ${emails.length}`;
                    email.countLine.hidden = false;
                    renderSimpleList(email.list, emails);
                    setCardStatus(email.badge, "ok", "OK");
                } else {
                    email.countLine.hidden = true;
                    email.list.innerHTML = "";
                    showMessage(email.message, "No public email addresses found.");
                    setCardStatus(email.badge, "empty", "None Found");
                }
            } else {
                email.countLine.hidden = true;
                email.list.innerHTML = "";
                showMessage(email.message, data.message || "Email harvesting unavailable.");
                setCardStatus(email.badge, "error", "Error");
            }
            return data;
        });
    }

    function runSocial(domainValue) {
        return postDomain("/social", domainValue).then((data) => {
            if (data.status === "success") {
                Object.keys(social.links).forEach((key) => {
                    const url = data.data[key];
                    if (url && url !== "Not Found") {
                        social.links[key].href = url;
                    }
                });
                hideMessage(social.message);
                social.list.hidden = false;
                setCardStatus(social.badge, "ok", "OK");
            } else {
                social.list.hidden = true;
                showMessage(social.message, data.message || "Social footprint unavailable.");
                setCardStatus(social.badge, "error", "Error");
            }
            return data;
        });
    }

    function runSubdomains(domainValue) {
        return postDomain("/subdomains", domainValue).then((data) => {
            if (data.status === "success") {
                subdomainItems = data.data.subdomains || [];
                subdomainPage = 0;
                hideMessage(subdomain.message);
                if (subdomainItems.length > 0) {
                    subdomain.countLine.textContent = `Total found: ${subdomainItems.length}`;
                    subdomain.countLine.hidden = false;
                    renderSubdomainPage();
                    setCardStatus(subdomain.badge, "ok", "OK");
                } else {
                    subdomain.countLine.hidden = true;
                    subdomain.list.innerHTML = "";
                    subdomain.pagination.hidden = true;
                    showMessage(subdomain.message, "No subdomains found.");
                    setCardStatus(subdomain.badge, "empty", "None Found");
                }
            } else {
                subdomainItems = [];
                subdomain.countLine.hidden = true;
                subdomain.list.innerHTML = "";
                subdomain.pagination.hidden = true;
                showMessage(subdomain.message, data.message || "Subdomain discovery unavailable.");
                setCardStatus(subdomain.badge, "error", "Error");
            }
            return data;
        });
    }

    // ---- OSINT Summary computation ---------------------------------------

    function classifyShodanStatus(data) {
        if (data.status === "success") {
            return "Active";
        }
        const message = (data.message || "").toLowerCase();
        if (message.includes("not configured")) return "API Key Missing";
        if (message.includes("invalid api key")) return "Invalid API Key";
        if (message.includes("query limit")) return "Query Limit Exceeded";
        if (message.includes("no shodan data")) return "No Data Found";
        if (message.includes("access denied")) return "Access Denied";
        if (message.includes("dns resolution failed")) return "Resolution Failed";
        if (message.includes("invalid ip")) return "Invalid IP";
        if (message.includes("network timeout")) return "Network Timeout";
        if (message.includes("connection error")) return "Connection Error";
        return "Unavailable";
    }

    function classifySslStatus(data) {
        if (data.status !== "success") {
            return "Unavailable";
        }
        const commonName = data.data.common_name;
        const validUntil = data.data.valid_until;
        if (!commonName || commonName === "Not Found") {
            return "No Certificate Found";
        }
        if (validUntil && validUntil !== "Not Found") {
            const parsed = new Date(validUntil);
            if (!isNaN(parsed.getTime())) {
                return parsed.getTime() >= Date.now() ? "Valid" : "Expired";
            }
        }
        return "Valid";
    }

    // Converts a single module's fetch result into the shape expected
    // by the server's report formatter: either the data dict on
    // success, or {"error": message} on failure. This lets the export
    // endpoints reuse exactly the data already collected during the
    // scan, instead of running any lookups again.
    function toReportSection(moduleResult) {
        return moduleResult.status === "success"
            ? moduleResult.data
            : { error: moduleResult.message || "Unavailable" };
    }

    function buildReportPayload(domainValue, results) {
        const [whoisData, dnsData, sslData, shodanData, emailData, subdomainData, socialData] = results;
        return {
            domain: domainValue,
            whois: toReportSection(whoisData),
            dns: toReportSection(dnsData),
            ssl: toReportSection(sslData),
            shodan: toReportSection(shodanData),
            email: toReportSection(emailData),
            subdomains: toReportSection(subdomainData),
            social: toReportSection(socialData),
        };
    }

    // Triggers a normal browser "Save As" download for an in-memory
    // Blob, without navigating away from the dashboard.
    function triggerBlobDownload(blob, filename) {
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
    }

    function updateSummary(domainValue, results) {
        const [whoisData, dnsData, sslData, shodanData, emailData, subdomainData] = results;

        summary.domain.textContent = domainValue;

        // Resolved IP: prefer the first DNS A record (independent of
        // whether the Shodan lookup itself succeeded).
        let resolvedIp = "Not Found";
        if (dnsData.status === "success" && Array.isArray(dnsData.data.A) && dnsData.data.A.length > 0) {
            resolvedIp = dnsData.data.A[0];
        } else if (shodanData.status === "success" && shodanData.data.ip) {
            resolvedIp = shodanData.data.ip;
        }
        summary.ip.textContent = resolvedIp;

        summary.registrar.textContent =
            whoisData.status === "success" ? formatValue(whoisData.data.registrar) : "Unavailable";
        summary.country.textContent =
            whoisData.status === "success" ? formatValue(whoisData.data.country) : "Unavailable";

        summary.sslStatus.textContent = classifySslStatus(sslData);
        summary.shodanStatus.textContent = classifyShodanStatus(shodanData);

        const subdomainCount =
            subdomainData.status === "success" ? (subdomainData.data.subdomains || []).length : 0;
        summary.subdomainCount.textContent = String(subdomainCount);

        const emailCount = emailData.status === "success" ? (emailData.data.emails || []).length : 0;
        summary.emailCount.textContent = String(emailCount);
    }

    // ---- Main "Start Recon" flow -----------------------------------------

    let lastReportPayload = null;

    downloadHtmlBtn.addEventListener("click", function (event) {
        event.preventDefault();
        if (!lastReportPayload) return;
        fetch("/report/export/html", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(lastReportPayload),
        })
            .then((response) => response.blob())
            .then((blob) => triggerBlobDownload(blob, `${lastReportPayload.domain}_report.html`))
            .catch(() => {
                scanMessage.textContent = "Could not generate the HTML report. Please try again.";
                scanMessage.className = "scan-message error";
                scanMessage.hidden = false;
            });
    });

    downloadPdfBtn.addEventListener("click", function (event) {
        event.preventDefault();
        if (!lastReportPayload) return;
        fetch("/report/export/pdf", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(lastReportPayload),
        })
            .then((response) => response.blob())
            .then((blob) => triggerBlobDownload(blob, `${lastReportPayload.domain}_report.pdf`))
            .catch(() => {
                scanMessage.textContent = "Could not generate the PDF report. Please try again.";
                scanMessage.className = "scan-message error";
                scanMessage.hidden = false;
            });
    });

    startBtn.addEventListener("click", function () {
        const domainValue = domainInput.value.trim();

        scanMessage.hidden = true;
        scanMessage.className = "scan-message";
        dashboard.hidden = true;
        downloadButtons.hidden = true;
        lastReportPayload = null;

        if (!domainValue) {
            scanMessage.textContent = "Please enter a domain.";
            scanMessage.className = "scan-message error";
            scanMessage.hidden = false;
            return;
        }

        loadingText.textContent = `Running reconnaissance scan on ${domainValue}...`;
        loadingIndicator.hidden = false;

        Promise.all([
            runWhois(domainValue),
            runDns(domainValue),
            runSsl(domainValue),
            runShodan(domainValue),
            runEmail(domainValue),
            runSubdomains(domainValue),
            runSocial(domainValue),
        ])
            .then((results) => {
                // results order matches the calls above.
                updateSummary(domainValue, results);
                lastReportPayload = buildReportPayload(domainValue, results);

                loadingIndicator.hidden = true;
                dashboard.hidden = false;

                scanMessage.textContent = `Scan complete for ${domainValue}.`;
                scanMessage.className = "scan-message";
                scanMessage.hidden = false;

                downloadButtons.hidden = false;
            })
            .catch(function () {
                loadingIndicator.hidden = true;
                scanMessage.textContent = "An unexpected error occurred while running the scan.";
                scanMessage.className = "scan-message error";
                scanMessage.hidden = false;
            });
    });
});
