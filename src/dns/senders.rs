//! Which third-party services a domain sends mail through, read from the `include:` entries of its own
//! SPF record. No network access here, so it is fully unit-tested.
//!
//! Only the domain's top-level includes count. Services often include other services inside their own
//! SPF records, and those would wrongly show up as senders of this domain.

use super::parse;

/// (SPF include domain, service name). An entry matches that domain and everything below it.
const PROVIDERS: &[(&str, &str)] = &[
    ("_spf.google.com", "Google Workspace"),
    ("spf.protection.outlook.com", "Microsoft 365"),
    ("icloud.com", "iCloud Mail"),
    ("zoho.com", "Zoho Mail"),
    ("zoho.eu", "Zoho Mail"),
    ("messagingengine.com", "Fastmail"),
    ("secureserver.net", "GoDaddy"),
    ("sendgrid.net", "SendGrid"),
    ("amazonses.com", "Amazon SES"),
    ("mailgun.org", "Mailgun"),
    ("spf.mtasv.net", "Postmark"),
    ("sparkpostmail.com", "SparkPost"),
    ("sendinblue.com", "Brevo"),
    ("brevo.com", "Brevo"),
    ("mailjet.com", "Mailjet"),
    ("mcsv.net", "Mailchimp"),
    ("mandrillapp.com", "Mandrill"),
    ("mktomail.com", "Marketo"),
    ("hubspotemail.net", "HubSpot"),
    ("_spf.salesforce.com", "Salesforce"),
    ("exacttarget.com", "Salesforce Marketing Cloud"),
    ("pardot.com", "Pardot"),
    ("mail.zendesk.com", "Zendesk"),
    ("helpscoutemail.com", "Help Scout"),
    ("intercom.io", "Intercom"),
    ("greenhouse.io", "Greenhouse"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
];

/// True if `target` is `domain` or a subdomain of it ("a.sendgrid.net" matches "sendgrid.net",
/// "notsendgrid.net" does not).
fn is_within(target: &str, domain: &str) -> bool {
    let t = target.to_ascii_lowercase();
    t == domain || t.strip_suffix(domain).is_some_and(|rest| rest.ends_with('.'))
}

/// Service names in the order the SPF record lists them, each once.
pub fn detect(spf_record: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for target in parse::spf_includes(&parse::spf_terms(spf_record)) {
        for (domain, name) in PROVIDERS {
            if is_within(&target, domain) && !found.iter().any(|n| n == name) {
                found.push((*name).to_string());
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_services_in_the_order_the_record_lists_them() {
        assert_eq!(detect("v=spf1 include:_spf.google.com include:sendgrid.net ~all"), ["Google Workspace", "SendGrid"]);
        assert_eq!(detect("v=spf1 include:amazonses.com include:mail.zendesk.com include:servers.mcsv.net -all"), ["Amazon SES", "Zendesk", "Mailchimp"]);
    }

    #[test]
    fn matches_whole_domains_only() {
        assert!(detect("v=spf1 include:notsendgrid.net ~all").is_empty());
        assert!(detect("v=spf1 include:sendgrid.net.evil.example ~all").is_empty());
        assert!(detect("v=spf1 include:google.com ~all").is_empty());
        assert_eq!(detect("v=spf1 include:u123.wl.sendgrid.net ~all"), ["SendGrid"]);
        assert_eq!(detect("v=spf1 include:SENDGRID.NET ~all"), ["SendGrid"]);
    }

    #[test]
    fn each_service_is_listed_once() {
        assert_eq!(detect("v=spf1 include:_spf.mailgun.org include:_spf.eu.mailgun.org ~all"), ["Mailgun"]);
        assert_eq!(detect("v=spf1 include:spf.sendinblue.com include:spf.brevo.com ~all"), ["Brevo"]);
    }

    #[test]
    fn qualifiers_and_macros_and_plain_records() {
        assert_eq!(detect("v=spf1 ~include:sendgrid.net -all"), ["SendGrid"]);
        assert!(detect("v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all").is_empty());
        assert!(detect("v=spf1 ip4:1.2.3.4 a mx -all").is_empty());
        assert!(detect("").is_empty());
    }

    #[test]
    fn real_records_seen_in_the_wild() {
        // github.com, stripe.com and hubspot.com style records, shortened
        assert_eq!(detect("v=spf1 include:_spf.google.com include:servers.mcsv.net include:mail.zendesk.com ~all"), ["Google Workspace", "Mailchimp", "Zendesk"]);
        assert_eq!(detect("v=spf1 include:3885857.spf06.hubspotemail.net include:_spf.salesforce.com ~all"), ["HubSpot", "Salesforce"]);
    }
}
