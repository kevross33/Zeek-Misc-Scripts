@load base/protocols/http

module HTTPFilter;

export {
    ## Any domain listed here will ignore the exact domain AND all of its subdomains (*.domain)
    const ignored_domains: set[string] = {
        "crl.microsoft.com",
        "windowsupdate.com",
        "msftconnecttest.com",
        "update.googleapis.com",
        "clients2.google.com",
        "msftncsi.com",
        "pki.core.windows.net",
        "cdn.office.net",
    } &redef;

    ## Any User-Agent containing these strings will be ignored
    const ignored_user_agents: pattern =
          /Microsoft-CryptoAPI/              # Windows certificate revocation checks
        | /Microsoft-Delivery-Optimization/  # Windows updates
        | /OfficeClickToRun/                 # O365 Update Check Stuff
        &redef;
}

# Helper function: returns True if the Host is an exact match OR a subdomain
function is_ignored_domain(host: string): bool
{
    if ( host in ignored_domains )
        return T;

    for ( domain in ignored_domains )
    {
        if ( ends_with(host, "." + domain) )
            return T;
    }

    return F;
}

hook HTTP::log_policy(rec: HTTP::Info, id: Log::ID, filter: Log::Filter)
{
    # 1. Filter by Domain (HTTP Host header)
    if ( rec?$host && is_ignored_domain(rec$host) )
        break;

    # 2. Filter by User-Agent (Regex pattern match)
    if ( rec?$user_agent && ignored_user_agents in rec$user_agent )
        break;
}
