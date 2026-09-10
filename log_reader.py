def read_log_file(filepath):
    new_log_file=list()
    try:
        with open(filepath,"r",encoding="utf-8") as dosya:
            for satir in dosya:
                new_log_file.append(satir.strip())
    except FileNotFoundError:
        print("file can not be found...:(")

    return new_log_file