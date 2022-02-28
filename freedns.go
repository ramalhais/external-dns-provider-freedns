package freedns

// read -s P
// AUTH_LOGIN=you@example.com AUTH_PASSWORD=$P ./build/external-dns --registry=txt --txt-owner-id=your-cluster-name --provider freedns --source=service --source=ingress --txt-prefix=xdns- --domain-filter=domain.example.com --once --dry-run --log-level=debug

import (
    "context"
    "strings"
    "math"
    // "fmt"
    // "os"

    log "github.com/sirupsen/logrus"

    "github.com/ramalhais/go-freedns"
    "sigs.k8s.io/external-dns/endpoint"
    "sigs.k8s.io/external-dns/plan"
    "sigs.k8s.io/external-dns/provider"
)

const minimumTTL = 3600

// FreeDNSProvider implements the DNS provider spec for UKFast FreeDNS.
type FreeDNSProvider struct {
    provider.BaseProvider
    Client *freedns.FreeDNS
    // Only consihosted zones managing domains ending in this suffix
    domainFilter     endpoint.DomainFilter
    DryRun           bool
}

func NewFreeDNSProvider(domainFilter endpoint.DomainFilter, dryRun bool) (*FreeDNSProvider, error) {
    freeDNS, err := freedns.NewFreeDNS()

    provider := &FreeDNSProvider{
        Client:       freeDNS,
        domainFilter: domainFilter,
        DryRun:       dryRun,
    }
    return provider, err
}

// Records returns a list of Endpoint resources created from all records in supported zones.
func (p *FreeDNSProvider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
    var endpoints []*endpoint.Endpoint

    domains, _, err := p.Client.GetDomains()
    if err != nil {
        return nil, err
    }

    zoneRecords := map[string]freedns.Record{}
    for domain, domain_id := range domains {
        if p.domainFilter.Match(domain) {
            records, _ := p.Client.GetRecords(domain_id)
            for recordID, record := range records {
                zoneRecords[recordID] = record
            }
        }
    }

    for _, r := range zoneRecords {
        if provider.SupportedRecordType(string(r.Type)) {
            endpoints = append(endpoints, endpoint.NewEndpointWithTTL(r.Name, string(r.Type), endpoint.TTL(minimumTTL), r.Value))
        }
    }
    return endpoints, nil
}

// ApplyChanges applies a given set of changes in a given zone.
func (p *FreeDNSProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
    dryRunText := ""
    if p.DryRun {
        dryRunText = "Dry-Run: "
    }

    // Identify the zone name for each record
    zoneNameIDMapper := provider.ZoneIDName{}

    domains, _, err := p.Client.GetDomains()
    if err != nil {
        return err
    }

    zoneRecords := map[string]freedns.Record{}
    for domain, domain_id := range domains {
        if p.domainFilter.Match(domain) {
            zoneNameIDMapper.Add(domain_id, domain)

            records, _ := p.Client.GetRecords(domain_id)
            for recordID, record := range records {
                zoneRecords[recordID] = record
            }
        }
    }

    for _, endpoint := range changes.Create {
        zoneId, zoneName := zoneNameIDMapper.FindZone(endpoint.DNSName)
        ttl := int(math.Max(minimumTTL, float64(endpoint.RecordTTL)))
        for _, target := range endpoint.Targets {
            log.WithFields(log.Fields{
                "zoneID":     zoneId,
                "zoneName":   zoneName,
                "dnsName":    endpoint.DNSName,
                "recordType": endpoint.RecordType,
                "target":     target,
                "TTL": 		  ttl,
            }).Infof("%sCreating record", dryRunText)
            if p.DryRun {
                continue
            }

            // Create DNS record
            recordName := strings.TrimSuffix(endpoint.DNSName, "."+zoneName)
            err = p.Client.CreateRecord(zoneId, recordName, endpoint.RecordType, target, string(ttl))
            if err != nil {
                return err
            }
        }
    }

    for _, endpoint := range changes.UpdateNew {
        // Currently iterates over each zoneRecord in ZoneRecords for each Endpoint
        // in UpdateNew; the same will go for Delete. As it's double-iteration,
        // that's O(n^2), which isn't great. No performance issues have been noted
        // thus far.

        // Find Zone
        zoneId, zoneName := zoneNameIDMapper.FindZone(endpoint.DNSName)

        var zoneRecord freedns.Record
        for _, target := range endpoint.Targets {
            for _, zr := range zoneRecords {
                if zr.Name == endpoint.DNSName && zr.Value == target {
                    zoneRecord = zr
                    break
                }
            }

            ttl := int(math.Max(minimumTTL, float64(endpoint.RecordTTL)))
            log.WithFields(log.Fields{
                "zoneId":     zoneId,
                "zoneName":   zoneName,
                "recordId":   zoneRecord.Id,
                "dnsName":    endpoint.DNSName,
                "recordType": endpoint.RecordType,
                "target":     target,
                "TTL":   	  ttl,
            }).Infof("%sPatching record", dryRunText)
            if p.DryRun {
                continue
            }
        
            recordName := strings.TrimSuffix(endpoint.DNSName, "."+zoneName)
            // Update DNS record
            err = p.Client.UpdateRecord(zoneId, zoneRecord.Id, recordName, endpoint.RecordType, target, string(ttl))
            if err != nil {
                return err
            }
        }
    }
    for _, endpoint := range changes.Delete {
        // As above, currently iterates in O(n^2). May be a good start for optimisations.
        var zoneRecord freedns.Record
        for _, zr := range zoneRecords {
            if zr.Name == endpoint.DNSName && string(zr.Type) == endpoint.RecordType {
                zoneRecord = zr
                break
            }
        }

        // Find Zone
        zoneId, zoneName := zoneNameIDMapper.FindZone(endpoint.DNSName)

        log.WithFields(log.Fields{
            "zoneId":     zoneId,
            "zoneName":   zoneName,
            "recordId":   zoneRecord.Id,
            "dnsName":    zoneRecord.Name,
            "recordType": zoneRecord.Type,
        }).Infof("%sDeleting record", dryRunText)
        if p.DryRun {
            continue
        }

        // Delete DNS record
        err = p.Client.DeleteRecord(zoneRecord.Id)
        if err != nil {
            return err
        }
    }
    return nil
}
