---
layout: post
title:  "Beware of BloodHound's Contains Edge"
date:   2022-06-14 00:00:00 -0500
categories: infosec
---
**2022-11-06:** Updated to take into account changes made into BloodHound 4.2.0.

As I continue my way through assessing Active Directory privileges without commercial software, I am constantly reminded how complex of a task it is. While determining the objects a single user can control is quite straight forward, finding all paths leading to the compromise of privileged principals can be tricky on a large domain. It is also apparent that in order to successfully do so, one must possess a strong understanding of the analyzed data, especially its weaknesses, or be at risk of reporting erroneous findings.

This post is dedicated to presenting the root cause of real-world scenario where if I did not take a close look at the data, I would have documented twice too many users with a path to domain administration privileges. It also includes a proposed solution so that you can also avoid it.

## The  Questionable Duality of Contains
[BloodHound](https://github.com/BloodHoundAD/BloodHound/)'s `Contains` edge aims to describe attack paths both from GPOs, and the potential of descendant objects inheriting permissions. Unfortunately, this cannot be achieved without introducing false positives as will be demonstrated.

### GPO to Domain Admins
Consider the following path:

<img src="/assets/img/bh-contains-edge/gpo-path-da.png" width="70%"/>

The GPO `GPO ROOT@AD.LOCAL` is linked at the root of the domain, but is not enforced as denoted by the dotted `GPLink` edge. This signifies that if a domain or OU in the path blocks GPO inheritance, it will not go down to the object that we wish to compromise, which would also be shown in the graph with a dotted `Contains` edge. Note that this is an entirely different concept than ACE inheritance, and typically does not matter much due to the possibility to enforce the GPO, resulting in a complete disregard of any blocked inheritance. In this demonstration, it is safe to ignore the state of the link, but is worth understanding.

Further down the path, the domain contains the well-known container `USERS@AD.LOCAL` that itself contains the group `DOMAIN ADMINS@AD.LOCAL`. Therefore, the `Contains` edges allow us to map that due to the GPO being linked at the root of the domain, it can use a filter that would apply to the members of the group that we want to compromise.

So far so good; no potential false positive in sight.

### ACE Inheritance to Domain Admins
Let us look at this next path:

<img src="/assets/img/bh-contains-edge/false-positive-path-da.png"/>

It is claimed that since the group `CL-UNI-ADMINGROUP1@AD.LOCAL` has `GenericAll` over the container where the group `DOMAIN ADMINS@AD.LOCAL` resides, it can be compromised. The idea would be to create, on the container, a new ACE that applies to descendant group objects, effectively awarding yourself privileges over the group; however, this is simply not possible since `Domain Admins` is a protected group.

[Protected accounts and groups](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) is an Active Directory feature that applies to specific high privileged accounts, groups and their members to ensure that no unwanted principals get privileges over them. An object named `AdminSDHolder` serves as a permissions template that overwrites protected principals' permissions every 60 minutes by default. Unless modified, this template has a very important property: it is configured to disable ACE inheritance.

Now, going back to the example above, `DOMAIN ADMINS@AD.LOCAL` does have ACE inheritance disabled, rendering the path impossible.

This leads to an interesting situation: in the context of a GPO, it is safe to trust the `Contains` edges, but in the case of an ACE that must be pushed down, they may yield false positives.

How can we successfully use the edge in both circumstances and avoid false positives? By not using it in both circumstances.

## Working on a Solution
In the previous section, we have established that any principal with ACE inheritance disabled leads to a false positive when an edge expects to compromise it that way. As such, deleting the `Contains` relationship would solve the issue, but would also introduce a blind spot in the case of a GPO; nonetheless, it is clear that the relationship is problematic, and must be dealt with.

### Finding Disabled Inheritance
When importing the output of the collection method `DCOnly` into BloodHound, the data set does not include the inheritance state of objects but fortunately, the collector does gather that information, and stores it in the JSON files that are ingested:

<img src="/assets/img/bh-contains-edge/json-isaclprotected.png"/>

Since the desired information cannot be found once imported, it means that the ingesting routine must be modified.

### Altering the Ingestor
In the release version 4.2.0 of BloodHound, the file `src/js/newingestion.js` contains a node creation function for each type of objects located in the JSON files. Since all these objects have the property `isACLProtected` set in the collected data, we can simply update each function using the same principle that will be shown. As an example, only the `buildGroupJsonNew` function will be updated.

Before the `queries.properties.props.push` function call, add the following two lines:

```
if (properties.distinguishedname !== undefined)
    properties.isaclprotected = group.IsACLProtected;
```

<img src="/assets/img/bh-contains-edge/modifying-buildgroupjsonnew.png"/>

The `if` comparison is used to avoid an odd behavior in the JSON where some objects such as groups are duplicated, but incomplete. In that case, they did not contain a distinguished name, so we refrain attempting to set the property. Also, GPOs do not have a distinguished name, and therefore the comparison must not be added in that function.

All that is left is to compile the code. This can be achieved easily using the third-party Docker image [electronuserland/builder](https://hub.docker.com/r/electronuserland/builder) as such at the root of the edited BloodHound project:

```
sudo docker run -it --rm -v ${PWD}:/project electronuserland/builder /bin/bash -c 'npm install && npm run-script build'
```

Once the compilation is complete, the newly created directory `BloodHound-linux-x64` contains the compiled binary when using Linux. Execute it and import your data as normally done. Feel free to open up the developer console by using the keys `Ctrl+Shift+I` to find out if any errors were encountered during the import.

At this point, nodes have the new `isaclprotected` property set, but relationships must also be adjusted to eliminate false positives.

### Reworking Relationships
As briefly mentioned earlier, deleting the `Contains` edge when ACE inheritance is disabled resolves false positives, but breaks paths from GPOs. Despite this, the edge must be deleted in that situation, so a way to restore paths from GPOs is needed.

Before executing any of the next queries, make sure to either backup your database (if you have the Enterprise version of Neo4j), or to have access to your collected data to avoid any misfortune.

In `cypher-shell`, execute the following queries:

```
MATCH (n:GPO)-[:GPLink|Contains*1..]->(m:User {isaclprotected: True}) CREATE (n)-[:DescendsTo]->(m);
MATCH (n:GPO)-[:GPLink|Contains*1..]->(m:Group {isaclprotected: True}) CREATE (n)-[:DescendsTo]->(m);
MATCH (n:GPO)-[:GPLink|Contains*1..]->(m:Computer {isaclprotected: True}) CREATE (n)-[:DescendsTo]->(m);
```

The idea is to add a new edge, here named `DescendsTo`, to link GPOs to all objects they can apply to that have ACE inheritance disabled. In a large domain with some GPOs linked at the root of the domain, this may yield a significant amount of newly-added edges, but does not matter much in my experience.

Now that we have linked GPOs to the objects where the path would be lost, we can go ahead and get rid of the `Contains` edges that are false positives in the case of ACE inheritance:

```
MATCH (n:Domain)-[r:Contains]->({isaclprotected: True}) DELETE r;
MATCH (n:Container)-[r:Contains]->({isaclprotected: True}) DELETE r;
MATCH (n:OU)-[r:Contains]->({isaclprotected: True}) DELETE r;
```

On all types of nodes that can contain other nodes, we delete the `Contains` relationship to the contained node when its ACE inheritance is disabled, successfully removing false positives.

Note that the ingestor could be modified to execute these queries at the end of an import to avoid this manual process.

### Validating the Results
After the previous manipulations, the GPO path described at the beginning of this post gets reported as such, but has two negative points:

<img src="/assets/img/bh-contains-edge/descendsto-gpo-path-da.png" width="70%"/>

1. We no longer see where the GPO is linked, and the path it has to take to compromise the user. This could be improved by adding a property to GPO objects depicting where they are linked, or simply query for its `GPLink` relationships. Then, we can use the distinguished name of the end object to reconstruct the path the GPO is taking.
2. Compromising a principal from a GPO is counted as only one relationship, and therefore risks of being reported more often when using the `shortestPath` function. Keep in mind that this problem is also true for many other cases, since all relationships have the same weight in the eyes of `shortestPath`. This leads to a chain of `MemberOf` costing more than a single `ForceChangePassword`, despite needing no operation on the domain to leverage the former.

Regardless, in my situation, these downsides are significantly easier to deal with than attempting to manually filter out false positives.

As our last validation, we query for the false positive mentioned earlier:

<img src="/assets/img/bh-contains-edge/resolved-false-positive-path-da.png" />

No path is returned due to the `Contains` edge getting deleted in the last section, as `DOMAIN ADMINS@AD.LOCAL` has ACE inheritance disabled.

## More Edge Removal
In this section, we diverge from the `Contains` edge, but remain on the topic of false positive reduction. Depending on your use case, you may be perfectly fine with ignoring the following edges, but in my situation they were problematic.

### The GetChanges Family
Prior to version 4.2.0, a singular edge did not exist to identify a principal with `DCSync` privileges; the analyst had to query for both `GetChanges` and `GetChangesAll`. Now, the `DCSync` edge is created post-processing when the aforementioned privileges are identified. This is convenient, but the `GetChanges` and `GetChangesAll` edges are not deleted afterwards, meaning that you may retrieve a path where a principal only has one of them, inducing a false positive.

The same concept applies to the new edge `SyncLAPSPassword` (technical details available [here](https://simondotsh.com/infosec/2022/07/11/dirsync.html)) combining `GetChanges` and `GetChangesInFilteredSet`.

For this reason, during my analysis, I delete the `GetChanges*` edges, but be aware that this has downsides. Consider the situation where a principal has `GetChanges`, but not `GetChangesAll`. If they have `GenericWrite` on a group that has the missing `GetChangesAll`, they could add themselves to the group and be able to perform the `DCSync`. If you delete these edges, you would end up missing this possibility.

If this fits your use case, you can delete the potentially false positive-inducing edges like so:
```
MATCH ()-[r:GetChanges]->() DELETE r;
MATCH ()-[r:GetChangesAll]->() DELETE r;
MATCH ()-[r:GetChangesInFilteredSet]->() DELETE r;
```

### TrustedBy
`TrustedBy` simply maps trusts between domains. While useful, it leads to erroneous paths when assessing cross-domain privileges.

Consider the next query and the resultant path:
```
MATCH p=shortestPath((:User {name: "WILLIAM_STEIN@AD.LOCAL"})-[*1..]->(:User {name: 'LOWPRIVS@AD2.LOCAL'})) RETURN p;
```

<img src="/assets/img/bh-contains-edge/trustedby-false-positive-path.png" />

`WILLIAM_STEIN@AD.LOCAL` has `DCSync` privileges over the domain `AD.LOCAL`. Then, `AD2.LOCAL` trusts `AD.LOCAL` for authentication, and it `Contains` the user `LOWPRIVS@AD2.LOCAL`.

The `DCSync` and `Contains` edges are accurate, but the trust mapping acts as if it awards privileges to push ACEs down the `AD2.LOCAL` domain object, which is absolutely not the case. A trust itself is not enough; `WILLIAM_STEIN@AD.LOCAL` would need to have been given privileges over `AD2.LOCAL` to successfully leverage this path.

The easiest solution is to get rid of the `TrustedBy` edges:

```
MATCH ()-[r:TrustedBy]->() DELETE r;
```

If need be, you can reimport the `*_domains.json` file from your BloodHound dump to restore the trust relationships.

## Concluding
While the proposed solution has negative aspects, it offers the peace of mind of knowing that the `Contains` edge will not introduce false positives. As I deem the fix imperfect, I will not be proposing it to the core of BloodHound, but recommend it to anyone assessing privileges at a large scale.

I would like to thank [marcan2020](https://twitter.com/marcan2020) for his contribution to the solution, and the [BadBlood](https://github.com/davidprowe/BadBlood) project for filling up my directories with plenty of data to play with.
