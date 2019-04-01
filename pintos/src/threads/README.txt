THE FOLLOWING IS A LIST OF STEPS THAT I TOOK IN ORDER TO CREATE
AND TEST ALARM-MEGA TEST. 

All files in U:\cis520\pintos\src\tests\threads\

Make.tests -> one change on line 5
Rubric.alarm -> addition line 4
tests.c -> addition line 16
alarm-mega.ck -> created new file mimicking alarm-multiple.ck

-- MAKE FAILED 

tests.h -> addition line 10
alarm-wait.c -> addition lines 27-31

-- MAKE SUCCESS (nav too build)
-- RUN OF pintos -v -- run alarm-mega SUCCESS
-- RUN OF pintos -v -- run alarm-mega >log-mega.txt same behavior as log-multiple.txt
-- log-multiple.txt is populated with results from test

--EUREKA

log-mega.txt AND log-multiple.txt LOCATED IN U:\cis520\pintos\src\threads