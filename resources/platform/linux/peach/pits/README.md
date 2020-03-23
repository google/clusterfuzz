#Adding a pit:

##STEP 1:
Make sure that your Peach pit is not incompatible. There are a few known
problems with pits that are not solved and will not work. The known problems
right now are:

    1) Pits that rely on of Fixups do not work.
    2) Pits that have a Padding field do not work EX: <Padding alignment="16" />
    3) Pits with Numbers that do not have size equal to 8, 16, 24, 32 or 64 do 
    not work

##STEP 2:
In order to add a pit to ClusterFuzz make sure the name of the file matches
with the name of the main Data Model. For example PDF.xml has the name of the 
data model as PDF.
There are many places this could be, but it is usually easy to spot as it will
be named something similar such as "PDFFileFormat" or "Pdf".
In order to maintain convention make the title all caps. 

##STEP 3:
Make sure the Pit is using the right type for numbers. Some Peach pits use hex 
values for their numbers without explicitly stating it is a hex. This will cause
the following error: `Peach.Engine.common.PeachException: Error: The default 
value for <Number> elements must be an integer.` To explicitly state it as a hex 
add the valueType field like so: 

`<Number name="Marker1" valueType="hex" value="FF E1" size="16" token="true"/>`


##STEP 4:
Delete the Run, Test, StateModel and Agent sections that might be
present. These are used for Peach fuzzing and will cause the error 
`Peach.Engine.common.PeachException: No sample data found matching requirements
 of <Data> element.`

Example:
``` 
<StateModel name="TheState" initialState="Initial">
       <State name="Initial">
         <Action type="output">
           <DataModel ref="AsfFileFormat"/>
           <Data name="data" fileName="C:\temp\wmt_part001.wmv"/>
         </Action>
         <Action type="close"/>
         <Action type="call" method="ScoobySnacks"/>
           </State>
     </StateModel>
     <Agent name="LocalAgent">
       <Monitor class="debugger.WindowsDebugEngine">
         <Param name="CommandLine" value="C:\Program Files\The KMPlayer\KMPlayer.exe fuzzed.asf"/>
         <Param name="StartOnCall" value="ScoobySnacks"/>
         <Param name="IgnoreFirstChanceGardPage" value="true"/>
       </Monitor>
       <Monitor class="process.PageHeap">
         <Param name="Executable" value="KMPlayer.exe"/>
       </Monitor>
     </Agent>
     <Test name="TheTest">
       <!--<Strategy class="rand.RandomMutationStrategy" switchCount="1500" maxFieldsToMutate="7"/>-->
       <Agent ref="LocalAgent"/>
       <StateModel ref="TheState"/>
       <Publisher class="file.FileWriterLauncherGui">
         <Param name="fileName" value="fuzzed.asf"/>
         <Param name="windowName" value="The KMPlayer"/>
         <Param name="debugger" value="true"/>
       </Publisher>
     </Test>
     <Run name="DefaultRun">
       <Test ref="TheTest"/>
       <Logger class="logger.Filesystem">
          <Param name="path" value="Z:\logs.asf.kmplayer"/>
       </Logger>
     </Run>
```