-- this is here so I can convert from databases that used the old cb-scala-unduplicator
-- format.  you shouldn't need it for normal use of fuse-sha1
begin transaction;
create temporary table files_backup(
  path varchar not null primary key,
  chksum varchar not null,
  symlink boolean default 0);
insert into files_backup select path, chksum, 0 from files;
drop table files;
create table files(
  path varchar not null primary key,
  chksum varchar not null,
  symlink boolean default 0);
insert into files select path, chksum, symlink from files_backup;
drop table files_backup;
commit;
vacuum;

-- this is here to convert databases that do not have a link column (indicating that a file has
-- been linked and should be first in line for deduping)
begin transaction;
create temporary table files_backup(
  path varchar not null primary key,
  chksum varchar not null,
  symlink boolean default 0,
  link boolean default 0);
insert into files_backup select path, chksum, symlink, 0 from files;
drop table files;
create table files(
  path varchar not null primary key,
  chksum varchar not null,
  symlink boolean default 0,
  link boolean default 0);
insert into files select path, chksum, symlink, link from files_backup;
drop table files_backup;
create index csum_idx on files(chksum);
commit;
vacuum;
