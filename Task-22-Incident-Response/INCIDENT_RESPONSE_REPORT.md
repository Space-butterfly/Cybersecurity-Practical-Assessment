# INCIDENT RESPONSE REPORT
## Accidental Exposure of an API Credential in a Public GitHub Repository

**Assessment Task:** Task 22 – The Secret Accidentally Published
**Incident Type:** Potential API Credential Exposure
**Severity:** High (Provisional)
**Environment:** Public GitHub Repository
**Prepared by:** Cybersecurity Assessment Team
**Date:** 30 October 2026

---

## 1. Executive Summary

A developer accidentally published a configuration file containing what appeared to be an API credential in a public GitHub repository. The file was reportedly deleted approximately five minutes after publication.

However, deleting the file does not guarantee that the credential is secure. The information may remain accessible through Git commit history, repository forks, cloned copies, cached content, or other sources.

This incident must therefore be treated as a potential credential compromise until an investigation establishes the credential's validity, exposure, and possible misuse.

The primary objectives are to:

1. Contain the exposure immediately.
2. Revoke or rotate the potentially exposed credential.
3. Investigate unauthorized access or usage.
4. Remove residual sensitive information where feasible.
5. Implement preventive security controls.

## 2. Incident Overview: Facts and Assumptions

### 2.1 Known Facts

Based on the scenario:

- A developer published a configuration file in a public repository.
- The file contained what appeared to be an API credential.
- The developer deleted the file approximately five minutes later.

### 2.2 Information Requiring Verification

The following details are not established by the scenario and must be investigated:

- Whether the credential was valid and active.
- Whether unauthorized individuals accessed or copied the credential.
- Whether the credential was used by unauthorized parties.
- Whether the credential remains in previous Git commits.
- Whether repository forks or cloned copies contain the file.
- Whether additional sensitive information was exposed.

**Important:** A public exposure does not automatically prove that an attacker accessed or misused the credential. Conclusions must be supported by evidence.

## 3. Prioritized Incident Response Plan

### Priority 1: Immediate Containment

The first priority is to prevent further unauthorized use of the potentially exposed credential.

Actions:

1. Identify the affected API credential and its service provider.
2. Immediately revoke the exposed credential or rotate it.
3. Generate a replacement credential using the provider's secure process.
4. Update legitimate applications and services with the replacement.
5. Test authorized applications to confirm that they function correctly.
6. Verify that the old credential is no longer accepted.
7. Temporarily restrict repository access if necessary during the investigation.

**Reason:** Deleting a file does not invalidate a credential that may already have been copied.

### Priority 2: Evidence Preservation

Preserve relevant evidence before performing repository cleanup or history rewriting.

Actions:

1. Record the affected repository URL.
2. Identify the commit containing the exposed configuration file.
3. Record the approximate publication and deletion timestamps.
4. Preserve relevant GitHub audit logs and repository activity.
5. Collect API provider authentication and usage logs.
6. Document credential revocation and replacement timestamps.
7. Maintain a record of all incident-response actions.

Evidence preservation should not delay credential revocation.

### Priority 3: Investigation and Verification

Investigate whether the exposed credential was accessed or misused.

Review the API provider's logs for:

- Unexpected API requests.
- Unknown IP addresses.
- Unusual geographic access patterns.
- Unexpected request frequency or traffic spikes.
- Unauthorized API operations.
- Unrecognized applications using the credential.
- Unusual resource consumption or billing activity.

Compare suspicious events with legitimate application activity.

If unauthorized use is identified:

- Determine the scope of unauthorized access.
- Identify potentially affected systems and data.
- Escalate the incident to the appropriate security team.
- Follow applicable contractual, organizational, and legal notification procedures.

If no suspicious activity is found, document the investigation period and the limitations of the available logs.

## 4. GitHub Repository Investigation

Deleting the configuration file from the latest version of the repository does not necessarily remove previous copies.

Investigate the following:

| Repository location | Required investigation |
|---|---|
| Git commit history | Check previous commits for the exposed file. |
| Branches and tags | Identify other references containing sensitive information. |
| Public forks | Determine whether forks contain the exposed content. |
| Cloned repositories | Consider that users may have downloaded copies. |
| Cached content | Investigate known cached or indexed copies where possible. |
| Pull requests | Check patches, discussions, and associated changes. |

### Removing Residual Sensitive Information

If the credential remains in Git history:

1. Follow GitHub's documented sensitive-data removal procedure.
2. Rewrite repository history where necessary.
3. Coordinate history rewriting with collaborators.
4. Assess known forks and other copies.
5. Request removal of cached sensitive content where applicable.
6. Verify the repository's accessible history after cleanup.

**Important:** History rewriting does not invalidate an exposed credential. Credential revocation or rotation must happen independently and immediately.

## 5. Root Cause Analysis

The exact root cause cannot be confirmed from the information provided. The following are possible contributing factors requiring investigation:

| Possible cause | Explanation |
|---|---|
| Insecure credential storage | API credentials may have been stored directly in a configuration file. |
| Accidental Git staging | The developer may have included a sensitive file in a commit unintentionally. |
| Missing secret scanning | Automated secret detection may not have been enabled. |
| Inadequate repository controls | Sensitive files may not have been properly excluded. |
| Insufficient code review | Changes may have been published without reviewing their contents. |

These are investigation hypotheses, not confirmed findings.

## 6. Preventive Security Recommendations

### 6.1 Secure Credential Management

- Never hardcode API keys or credentials in source code.
- Use dedicated secret-management solutions.
- Store sensitive configuration values securely.
- Use environment variables or approved secret-injection mechanisms.
- Apply the principle of least privilege.
- Establish credential expiration and rotation policies.

### 6.2 GitHub Security Controls

- Configure `.gitignore` to exclude local secret files.
- Enable GitHub secret scanning where available.
- Enable push protection where available.
- Review staged files before committing.
- Perform code reviews before merging or publishing changes.
- Audit repository permissions and access controls.

A `.gitignore` file is not sufficient protection for secrets that have already been tracked by Git.

### 6.3 Monitoring and Detection

- Monitor API credential usage.
- Enable alerts for unusual API activity.
- Review authentication and audit logs regularly.
- Monitor unexpected resource consumption and billing.
- Periodically audit active credentials and their permissions.

### 6.4 Developer Awareness

- Train developers to identify sensitive information.
- Establish secure configuration-management procedures.
- Include secret-exposure checks in code reviews.
- Conduct periodic security awareness exercises.
- Document procedures for reporting accidental credential exposure.

## 7. Incident Response Timeline

| Stage | Action |
|---|---|
| Detection | Identify the exposed configuration file. |
| Immediate containment | Revoke or rotate the credential. |
| Evidence preservation | Record commits, timestamps, and relevant logs. |
| Investigation | Examine API activity and repository history. |
| Eradication | Remove residual sensitive information where feasible. |
| Recovery | Deploy replacement credentials and verify applications. |
| Lessons learned | Implement preventive controls and document findings. |

## 8. Verification Checklist

The incident should not be considered fully resolved until the following activities have been completed:

- [ ] Exposed credential revoked or rotated.
- [ ] Replacement credential generated and tested.
- [ ] Old credential confirmed invalid.
- [ ] API provider logs reviewed.
- [ ] Suspicious API activity investigated.
- [ ] Git commit history examined.
- [ ] Branches, tags, and known forks assessed.
- [ ] Residual sensitive content addressed where feasible.
- [ ] Repository access and security settings reviewed.
- [ ] Preventive security controls implemented.
- [ ] Incident timeline and findings documented.

Any unavailable evidence or remaining uncertainty must be recorded in the final incident findings.

## 9. Conclusion

An API credential accidentally published in a public repository must be treated as potentially compromised, even if the file is deleted within a few minutes.

The correct incident-response approach begins with immediate credential revocation or rotation, followed by evidence preservation, investigation of API activity, and examination of repository history.

Long-term prevention requires secure credential storage, automated secret scanning, push protection, least-privilege access, monitoring, and developer awareness.

The most important security lesson is that deleting exposed information does not undo its disclosure. Effective incident response requires containment, investigation, eradication, recovery, and prevention.

## 10. References

1. **NIST Special Publication 800-61 Revision 3** – Incident Response Recommendations and Considerations for Cybersecurity Risk Management.
   https://csrc.nist.gov/pubs/sp/800/61/r3/final

2. **OWASP Secrets Management Cheat Sheet** – Secure storage, management, and rotation of secrets.
   https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

3. **GitHub Documentation** – Removing sensitive data from a repository.
   https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository

4. **GitHub Documentation** – About secret scanning.
   https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning

5. **GitHub Documentation** – About push protection.
   https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection

---

**End of Report**
