# WebLog2Mysql

Transform Web logs files to Mysql database

## SQL

```
 SELECT LEFT(`date`, 10) as D, count(*), sum(`size`) FROM tmp_logs.logs
 where LEFT(`date`,7) = '2016-11'
 group by D
 order by D DESC
```

