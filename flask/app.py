import os
from flask import Flask, render_template, request
from investigation import *
 
app = Flask(__name__)
 

@app.route("/",methods=["GET","POST"])
def index():
    if request.method=="GET":
        return render_template("index.html")
    if request.method=="POST":
        if 'pcapfile' not in request.files:
            return render_template("index.html", error="File not in the form.")
        pcap=request.files["pcapfile"]
        if pcap.filename == '':
            return render_template("index.html", error="No selected file")
        allowed_extensions = {'pcap', 'pcapng'}
        if '.' not in pcap.filename or pcap.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
            return render_template("index.html", error="Invalid file extension")
        
        if os.path.exists("uploads"): #if any file is already present, delete them so one analysis of the file could be done.
            files = os.listdir("uploads")
            if len(files) > 0:
                for file in files:
                    file_path = os.path.join("uploads", file)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                        
        pcap.save('uploads/' + pcap.filename)
        return render_template("index.html", error="File uploaded Successfully.")

#--------------------------------------------------------------------
@app.route("/investigate",methods=["GET","POST"])
def investigate():
    if request.method=="GET":
        return render_template("investigate.html")
    if request.method=="POST":
        select=request.form.get("scan")
        if select=="magic_bytes_find_all":
            files = os.listdir("uploads")
            if len(files)>1:
                return render_template("investigate.html",result=f"Please upload the file again. there are more than 1 files in the uploads folder.")
            if len(files)==0:
                return render_template("investigate.html",result=f"Please upload the file again. there is no file found in uploads folder. Please make sure to upload file via web from / endpoint.")
            if  str(files[0]).endswith("pcap"):
                dataS=magic_bytes_find_all(f"uploads/{str(files[0])}")
                listData=[]
                for i in dataS:
                    templist=[i,dataS[i]["number"]]
                    listData.append(templist)
                return render_template("investigate.html",magic_bytes_find_all=listData)
            else:
                return render_template("investigate.html",result="Please upload valid pcap file ending with .pcap")
                
                
        if select=="file_scan":
            files = os.listdir("uploads")
            if len(files)>1:
                return render_template("investigate.html",result=f"Please upload the file again. there are more than 1 files in the uploads folder.")
            if len(files)==0:
                return render_template("investigate.html",result=f"Please upload the file again. there is no file found in uploads folder. Please make sure to upload file via web from / endpoint.")
            if  str(files[0]).endswith("pcap"):
                dataS=file_scan(f"uploads/{str(files[0])}")
                return render_template("investigate.html",file_scan=dataS)
            else:
                return render_template("investigate.html",result="Please upload valid pcap file ending with .pcap")
                
    return render_template("investigate.html",result=f"You selected {str(select)}")
 
 
 
if __name__ == "__main__":
    app.run()