@mkdir ..\..\telsa\build-win\include\libetpan
@for /F "delims=" %%a in (build_headers.list) do @copy "..\%%a" ..\..\telsa\build-win\include\libetpan
@echo "done" >_headers_depends