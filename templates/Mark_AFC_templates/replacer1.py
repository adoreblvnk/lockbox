import re
output_file = open("output.txt", "w+")
pattern = ',"sov_a3.+?Admin-0 country"'
p1 = '"scale.+?labelrank":\d,'
with open ('cs1.js', 'r' ) as f:
    content = f.read()
    content_new = re.sub(pattern, '',content, flags = re.M)
    c3 = re.sub(p1, '"views":0,',content_new, flags = re.M)
    
output_file.write(c3)
