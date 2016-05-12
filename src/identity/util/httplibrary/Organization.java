package identity.util.httplibrary;

/**
 * Created by vtaneja on 8/27/15.
 */
public class Organization {

    public String getAccount() {
        return Account;
    }

    public void setAccount(String account) {
        Account = account;
    }

    public String getActive() {
        return Active;
    }

    public void setActive(String active) {
        Active = active;
    }

    public String getCreatedDate() {
        return CreatedDate;
    }

    public void setCreatedDate(String createdDate) {
        CreatedDate = createdDate;
    }

    public String getOrgId() {
        return OrgId;
    }

    public void setOrgId(String orgId) {
        OrgId = orgId;
    }

    public String getName() {
        return Name;
    }

    public void setName(String name) {
        Name = name;
    }

    public String getOrganizationType() {
        return OrganizationType;
    }

    public void setOrganizationType(String organizationType) {
        OrganizationType = organizationType;
    }

    public String getServer() {
        return Server;
    }

    public void setServer(String server) {
        Server = server;
    }

    public String getSignupCountryIsoCode() {
        return SignupCountryIsoCode;
    }

    public void setSignupCountryIsoCode(String signupCountryIsoCode) {
        SignupCountryIsoCode = signupCountryIsoCode;
    }

    public String getStatus() {
        return Status;
    }

    public void setStatus(String status) {
        Status = status;
    }

    private String Account;
    private String Active;
    private String CreatedDate;
    private String OrgId;
    private String Name;
    private String OrganizationType;
    private String Server;
    private String SignupCountryIsoCode;
    private String Status;

    public Organization(String Account, String Active, String CreatedDate, String OrgId, String Name, String OrganizationType,
                        String Server, String SignupCountryIsoCode, String Status) {
        super();
        this.Account = Account;
        this.Active = Active;
        this.CreatedDate = CreatedDate;
        this.OrgId = OrgId;
        this.Name = Name;
        this.OrganizationType = OrganizationType;
        this.Server = Server;
        this.SignupCountryIsoCode = SignupCountryIsoCode;
        this.Status = Status;
    }
}
