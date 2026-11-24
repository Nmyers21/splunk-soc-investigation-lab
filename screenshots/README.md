# Splunk investigation evidence

Ten analyst-supplied screenshots are included in the repository. They document manual queries and an alert-configuration form, not proof that a scheduled alert ran or triggered. They contain synthetic training identities and documentation addresses. Review future captures for real secrets or private information before including them.

| File | Evidence |
| --- | --- |
| [01_failed_logins_by_account.png](01_failed_logins_by_account.png) | failed logins by account |
| [02_failed_logins_by_account_and_source.png](02_failed_logins_by_account_and_source.png) | failed logins by account and source |
| [03_account_authentication_timeline.png](03_account_authentication_timeline.png) | account authentication timeline |
| [04_authentication_outcome_counts.png](04_authentication_outcome_counts.png) | authentication outcome counts |
| [05_authentication_timeline_with_logon_type.png](05_authentication_timeline_with_logon_type.png) | authentication timeline with logon type |
| [06_post_authentication_account_activity.png](06_post_authentication_account_activity.png) | post authentication account activity |
| [07_failed_authentication_account_breadth_by_source.png](07_failed_authentication_account_breadth_by_source.png) | failed authentication account breadth by source |
| [08_authentication_outcomes_by_account_for_source.png](08_authentication_outcomes_by_account_for_source.png) | authentication outcomes by account for source |
| [09_account_breadth_in_15_minute_windows.png](09_account_breadth_in_15_minute_windows.png) | account breadth in 15 minute windows |
| [10_password_spraying_alert_configuration.png](10_password_spraying_alert_configuration.png) | password spraying alert configuration |

The incident report references the first six captures using relative image links. `.gitignore` explicitly includes these ten reviewed PNG files; other future images remain excluded until reviewed.
