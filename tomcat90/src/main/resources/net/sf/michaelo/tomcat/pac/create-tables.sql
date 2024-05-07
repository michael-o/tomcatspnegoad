create table kerb_validation_info (
pacId integer primary key,
effectiveName text not null,
fullName text not null,
logonScript text not null,
profilePath text not null,
homeDirectory text not null,
homeDirectoryDrive text not null,
userId integer not null,
primaryGroupId integer not null,
userFlags integer not null,
logonServer text not null,
logonDomainName text not null,
logonDomainId text not null,
userAccountControl integer not null,
resourceGroupDomainSid text
);

create table group_ids (
id integer primary key autoincrement,
pacId integer references kerb_validation_info(pacId) on delete cascade,
relativeId integer not null,
attributes integer not null
);

create table extra_sids (
id integer primary key autoincrement,
pacId integer references kerb_validation_info(pacId) on delete cascade,
sid text not null,
attributes integer not null
);

create table resource_group_ids (
id integer primary key autoincrement,
pacId integer references kerb_validation_info(pacId) on delete cascade,
relativeId integer not null,
attributes integer not null
);

create table upn_dns_info (
pacId integer primary key,
upn text not null,
dnsDomainName text not null,
flags integer not null,
samName text,
sid text
);
