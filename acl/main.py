from pybatfish.client.commands import *
from pybatfish.question.question import load_questions, list_questions
from pybatfish.question import bfq
from pybatfish.datamodel.flow import *

load_questions()
CURRENT_SNAPSHOT_NAME = "current"
CURRENT_SNAPSHOT_PATH = "network/current"
CANDIDATE1_SNAPSHOT_NAME = "candidate1"
CANDIDATE1_SNAPSHOT_PATH = "network/candidate1"
CANDIDATE2_SNAPSHOT_NAME = "candidate2"
CANDIDATE2_SNAPSHOT_PATH = "network/candidate2"


bf_set_network("network-filters")
bf_init_snapshot(CURRENT_SNAPSHOT_PATH, name=CURRENT_SNAPSHOT_NAME, overwrite=True)
bf_init_snapshot(CANDIDATE1_SNAPSHOT_PATH, name=CANDIDATE1_SNAPSHOT_NAME, overwrite=True)
bf_init_snapshot(CANDIDATE2_SNAPSHOT_PATH, name=CANDIDATE2_SNAPSHOT_NAME, overwrite=True)

node_name = "eos-acl"
filter_name = "acl_in"

traffic1 = HeaderConstraints(srcIps="192.168.2.0/24",
                            dstIps="192.168.1.4/32, 192.168.1.5/32",
                            ipProtocols=["tcp"],
                            dstPorts="80,8080")
traffic2 = HeaderConstraints(srcIps="192.168.2.0/24",
                            dstIps="192.168.1.0 \ (192.168.1.4, 192.168.1.5)",
                            ipProtocols=["tcp"],
                            dstPorts="80,8080")
currentdeny = bfq.searchFilters(headers=traffic1,
                           filters=filter_name,
                           nodes=node_name,
                           action="deny").answer(
                               snapshot=CURRENT_SNAPSHOT_NAME
                           )
# No output indicates the traffic was permitted, i.e. find flows that match this search
print(currentdeny.frame())

# testing the opposite case.. here we see that there is no traffic permitted that 
# isn't destined for those two hosts
currentpermit = bfq.searchFilters(headers=traffic2,
                           filters=filter_name,
                           nodes=node_name,
                           action="permit").answer(
                               snapshot=CURRENT_SNAPSHOT_NAME
                           )
print(currentpermit.frame())
# pybatfish.client.asserts.assert_filter_denies(filters, headers, startLocation=None, soft=False, snapshot=None, session=None, df_format='table')

answer2 = bfq.searchFilters(headers=traffic1,
                           filters=filter_name,
                           nodes=node_name,
                           action="deny").answer(
                               snapshot=CANDIDATE1_SNAPSHOT_NAME
                           )
print ("Candidate 1 result")
print(answer2.frame())
# No output indicates the traffic was permitted, i.e. find flows that match this search
answer3 = bfq.searchFilters(headers=traffic1,
                           filters=filter_name,
                           nodes=node_name,
                           action="deny").answer(
                               snapshot=CANDIDATE2_SNAPSHOT_NAME
                           )
print ("Candidate 2 result")
print(answer3.frame())

# path = PathConstraints(startLocation="")
# headers = HeaderConstraints(srcIps="0.0.0.0/0", dstIps="192.168.1.0/24", applications="SSH")
# reach = bfq.reachability(headers=headers).answer().frame()
# print(reach)