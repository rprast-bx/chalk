#!/usr/bin/env python
import person


if __name__ == "__main__":
    p = person.Person(name="aaa", age=12)
    print(p.toJson())
# { "MAGIC" : "dadfedabbadabbed", "CHALK_ID" : "C4W62R-HS69-J3JC-K4CSJ6", "CHALK_VERSION" : "0.2.2", "TIMESTAMP_WHEN_CHALKED" : 1703173284113, "DATETIME_WHEN_CHALKED" : "2023-12-21T10:41:18.691-05:00", "ARTIFACT_TYPE" : "python", "CHALK_RAND" : "67989bb4f6fe58cf", "CODE_OWNERS" : "* @viega\n", "HASH" : "a8ab92d92dfdeb4f66d895c5963882d9e905df7c7ecd74463d91a5063d14691b", "INJECTOR_COMMIT_ID" : "65770ba03a8b839b9a4c9907a3eff2924db102bc", "PLATFORM_WHEN_CHALKED" : "GNU/Linux x86_64", "METADATA_ID" : "2Y472M-0BKB-WQ5B-N1B1ME" }
