@load base/protocols/ssl

module SSLFilter;

export {
    # Any domain listed here will ignore the exact domain AND all of its subdomains (*.domain)
    const ignored_domains: set[string] = {
        # Microsoft Defender & Microsoft noisy telemetry
        "endpoint.security.microsoft.com",
        "defender.microsoft.com",
        "wd.microsoft.com",
        "wdcp.microsoft.com",
        "wdcpalt.microsoft.com",
        "smartscreen.microsoft.com",
        "smartscreen-prod.microsoft.com",
        "data.microsoft.com",
        "definitionupdates.microsoft.com",
        "checkappexec.microsoft.com",
        "urs.microsoft.com",
        "atp.azure.com",
        "winatp-gw-ukw.microsoft.com",
        "events.data.microsoft.com",
        "client.wns.windows.com",
        "telemetry.microsoft.com",
        "azure-devices.net",
        "manage.microsoft.com",
        "update.microsoft.com",
        "onecdn.static.microsoft",
        "cdn.office.net",
        "config.office.net",
        "edge.microsoft.com",
        "arc.azure.com",
        "aria.microsoft.com",
        "mp.microsoft.com",
        "autopatch.microsoft.com",
        # Other things
        "android.clients.google.com",
    } &redef;
}

function is_ignored_domain(sni: string): bool
{
    if ( sni in ignored_domains )
        return T;

    for ( domain in ignored_domains )
    {
        if ( ends_with(sni, "." + domain) )
            return T;
    }

    return F;
}

hook SSL::log_policy(rec: SSL::Info, id: Log::ID, filter: Log::Filter)
{
    if ( rec?$server_name && is_ignored_domain(rec$server_name) )
        break;
}
